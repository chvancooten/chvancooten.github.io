// WebGL2 renderer for the particle world. There are no vertex buffers: every particle is derived from gl_InstanceID
// in the vertex shader, so a frame is a few uniforms and a handful of draw calls, whatever the particle count.
//
// A frame renders one or more views of the world (the landing and the windows between the chapters), each with its
// own camera, into one canvas:
// 1. Background, at a quarter of the resolution: the page colour, soft glows at the views' focal points, a vignette,
//    inside the union of the views' rectangles.
// 2. Particles, per view: trails (short ribbons through each particle's recent positions) and heads (capsules from
//    its position at the shutter opening to its position now, each projected with the camera of that instant, so a
//    streak is the true screen motion). Depth of field, a sub-pixel fade and depth fog come from the projected depth.
//    Each view is masked to its own rectangle (feathered inside) and to its composition veils. The particles are
//    accumulated as premultiplied ink and coverage (the sums of c*a and a), not blended onto the page.
// 3. Composite: the colour is the coverage-weighted mean of the inks, so a dense red region stays red and a dense
//    blue one stays blue (never orange, never white), and two inks only mix where they overlap. The strength is
//    1 - exp(-g * coverage). Dark: added to the page, at most (1 + overdrive) times the ink's own brightness, a cap
//    that keeps blue from washing out to white. Light: laid over the paper like ink (a mix in OKLab), never
//    subtracted, so nothing looks inverted.
// Shader programs compile without blocking the main thread: completion is polled (KHR_parallel_shader_compile, or a
// fence where the extension is missing) before any status is queried.

const HEADER = `#version 300 es
precision highp float;
precision highp int;
uniform mat4 uVP;
uniform mat4 uVPp;
uniform vec2 uRes;
uniform float uFocal;
uniform float uDpr;
uniform vec4 uTime;
uniform vec4 uLens;
uniform vec4 uFog;
uniform float uGain;
uniform vec3 uInk[6];
uniform float uN;
uniform vec4 uP;
struct Pt { vec3 p; vec3 c; float a; float s; };
uvec3 pcg3(uvec3 v){v=v*1664525u+1013904223u;v.x+=v.y*v.z;v.y+=v.z*v.x;v.z+=v.x*v.y;v^=v>>16u;v.x+=v.y*v.z;v.y+=v.z*v.x;v.z+=v.x*v.y;return v;}
vec4 hash4(uint i){uvec3 a=pcg3(uvec3(i,i^0x9e3779b9u,7u));uvec3 b=pcg3(uvec3(a.z,i,0x85ebca6bu));return vec4(a.x,a.y,a.z,b.x)*(1.0/4294967296.0);}
float fogAt(float d){return smoothstep(uFog.z,uFog.w,d)*exp(-max(d-uFog.x,0.)*uFog.y);}
`;

// Screen-space shading in device pixels: the view's rectangles (uMask.x 1: shown only inside them, each feathered
// inside by its own width; 0: everywhere) and the composition veils that keep the copy legible: a column on the left
// (uVeil.xy), a band at the bottom (uVeil.zw) and one at the top (uVeil2.xy; uVeil2.z is their feather, uVeil2.w the
// frame height).
const SHADE = `
uniform vec4 uMask;
uniform vec4 uRects[8];
uniform float uRectF[8];
uniform vec4 uVeil;
uniform vec4 uVeil2;
float sdBox(vec2 p,vec4 r){vec2 c=(r.xy+r.zw)*.5,e=(r.zw-r.xy)*.5;vec2 d=abs(p-c)-e;return length(max(d,0.))+min(max(d.x,d.y),0.);}
float shade(vec2 p){
  float m=1.;
  if(uMask.x>.5){
    m=0.;
    for(int i=0;i<8;i++){
      if(float(i)>=uMask.z)break;
      m=max(m,smoothstep(0.,max(uRectF[i],1.),-sdBox(p,uRects[i])));
    }
  }
  float f=max(uVeil2.z,1.);
  if(uVeil.y>0.)m*=1.-uVeil.y*(1.-smoothstep(uVeil.x,uVeil.x+f,p.x));
  if(uVeil.w>0.)m*=1.-uVeil.w*(1.-smoothstep(uVeil.z,uVeil.z+f,p.y));
  if(uVeil2.y>0.)m*=1.-uVeil2.y*smoothstep(uVeil2.w-uVeil2.x-f,uVeil2.w-uVeil2.x,p.y);
  return m;
}
`;

const CULL = "gl_Position=vec4(-9.,-9.,0.,1.);";

const HEAD_VS = (world) => `${HEADER}
${world}
out vec2 vQ;
out vec3 vS;
out vec4 vC;
void main(){
  uint id=uint(gl_InstanceID);
  vec4 h=hash4(id);
  Pt a=particle(id,h,uTime.x,uTime.y);
  Pt b=particle(id,h,uTime.z,uTime.w);
  vec4 c0=uVP*vec4(a.p,1.);
  vec4 c1=uVPp*vec4(b.p,1.);
  float d=c0.w;
  float al=a.a*uGain*fogAt(d);
  if(d<.05||al<.0015){${CULL}vQ=vec2(0.);vS=vec3(1.);vC=vec4(0.);return;}
  if(c1.w<.05)c1=c0;
  vec2 s0=(c0.xy/c0.w*.5+.5)*uRes;
  vec2 s1=(c1.xy/c1.w*.5+.5)*uRes;
  float r=abs(a.s)*uFocal/d*uLens.w;
  float blur=min(uLens.y*abs(d-uLens.x)/d,uLens.z);
  float re=sqrt(r*r+blur*blur);
  al*=pow(r/re,1.35);
  float mr=.85*uDpr;
  if(re<mr){al*=(re/mr)*(re/mr);re=mr;}
  vec2 dv=s0-s1;
  float L=length(dv);
  float Lm=uRes.y*.42;
  if(L>Lm){dv*=Lm/L;L=Lm;}
  al*=pow(2.*re/(2.*re+L),.62);
  vec2 dir=L>1e-3?dv/L:vec2(1.,0.);
  vec2 nr=vec2(-dir.y,dir.x);
  vec2 cr=vec2(float(gl_VertexID&1),float(gl_VertexID>>1))*2.-1.;
  float hl=L*.5+re;
  vec2 px=s0-dv*.5+dir*cr.x*hl+nr*cr.y*re;
  vQ=vec2(cr.x*hl,cr.y*re);
  vS=vec3(L*.5,re,smoothstep(1.6*uDpr,7.*uDpr,blur));
  vC=vec4(a.c*al,al);
  gl_Position=vec4(px/uRes*2.-1.,0.,1.);
}`;

const HEAD_FS = `#version 300 es
precision highp float;
${SHADE}
in vec2 vQ;
in vec3 vS;
in vec4 vC;
uniform float uAccS;
out vec4 o;
void main(){
  float q=length(vec2(max(abs(vQ.x)-vS.x,0.),vQ.y))/vS.y;
  float g=exp(-q*q*4.2);
  float disc=(1.-smoothstep(.62,1.,q))*(.8+.2*smoothstep(.3,.8,q));
  o=vC*(mix(g,disc*.4,vS.z)*step(q,1.)*shade(gl_FragCoord.xy)*uAccS);
}`;

const SEG = 5; // trail segments
const TRAIL_VS = (world) => `${HEADER}
${world}
uniform vec3 uTrail;
out float vV;
out vec4 vC;
void main(){
  int i=gl_VertexID>>1;
  float side=float(gl_VertexID&1)*2.-1.;
  uint id=uint(gl_InstanceID);
  vec4 h=hash4(id);
  float u=float(i)/${SEG}.;
  int j=i<${SEG}?i+1:i-1;
  float uj=float(j)/${SEG}.;
  Pt a=particle(id,h,uTime.x-uTrail.x*u,uTime.y-uTrail.x*u);
  Pt b=particle(id,h,uTime.x-uTrail.x*uj,uTime.y-uTrail.x*uj);
  vec4 ca=uVP*vec4(a.p,1.);
  vec4 cb=uVP*vec4(b.p,1.);
  float d=ca.w;
  float al=a.a*uGain*uTrail.z*fogAt(d);
  if(d<.05||cb.w<.05||al<.001){${CULL}vV=0.;vC=vec4(0.);return;}
  vec2 sa=(ca.xy/ca.w*.5+.5)*uRes;
  vec2 sb=(cb.xy/cb.w*.5+.5)*uRes;
  vec2 dv=i<${SEG}?sb-sa:sa-sb;
  float L=length(dv);
  if(L>uRes.y*.16)al=0.;
  al*=pow(min(1.,22.*uDpr/max(L,1e-3)),.6);
  vec2 dir=L>1e-4?dv/L:vec2(1.,0.);
  vec2 nr=vec2(-dir.y,dir.x);
  float r=a.s*uFocal/d*uLens.w*uTrail.y;
  float blur=min(uLens.y*abs(d-uLens.x)/d,uLens.z);
  float re=sqrt(r*r+.25*blur*blur);
  al*=r/re;
  float mr=.7*uDpr;
  if(re<mr){al*=re/mr;re=mr;}
  al*=pow(1.-u,1.35)*smoothstep(0.,.12,u+.02);
  vV=side;
  vC=vec4(a.c*al,al);
  gl_Position=vec4((sa+nr*side*re)/uRes*2.-1.,0.,1.);
}`;

const TRAIL_FS = `#version 300 es
precision highp float;
${SHADE}
in float vV;
in vec4 vC;
uniform float uAccS;
out vec4 o;
void main(){o=vC*(exp(-vV*vV*2.6)*shade(gl_FragCoord.xy)*uAccS);}`;

const FULL_VS = `#version 300 es
void main(){vec2 p=vec2(float((gl_VertexID<<1)&2),float(gl_VertexID&2));gl_Position=vec4(p*2.-1.,0.,1.);}`;

const NG = 6; // glow slots
const BG_FS = `#version 300 es
precision highp float;
${SHADE}
uniform vec2 uRes;
uniform vec3 uBg;
uniform float uLight;
uniform vec4 uG[${NG}];
uniform vec3 uGC[${NG}];
uniform float uVig;
uniform float uPS;
out vec4 o;
void main(){
  vec2 p=gl_FragCoord.xy*uPS;
  vec3 c=uBg,gl=vec3(0.);
  for(int i=0;i<${NG};i++){
    vec2 d=(p-uG[i].xy)/max(uG[i].z,1.);
    gl+=(uLight>.5?uGC[i]-uBg:uGC[i])*uG[i].w*exp(-dot(d,d));
  }
  c+=gl*shade(p);
  vec2 v=p/uRes-.5;
  v.x*=uRes.x/uRes.y;
  float vg=uVig*dot(v,v);
  o=vec4(uLight>.5?c-vec3(.035,.045,.03)*vg:c*(1.-vg),1.);
}`;

const COMP_FS = `#version 300 es
precision highp float;
uniform sampler2D uAcc;
uniform sampler2D uBgT;
uniform vec2 uRes;
uniform float uLight;
uniform float uSeed;
uniform vec3 uComp;
out vec4 o;
vec3 lin(vec3 c){return mix(c/12.92,pow((c+.055)/1.055,vec3(2.4)),step(.04045,c));}
vec3 gam(vec3 c){c=max(c,vec3(0.));return mix(c*12.92,1.055*pow(c,vec3(1./2.4))-.055,step(.0031308,c));}
vec3 toLab(vec3 c){c=lin(c);
  vec3 m=pow(max(vec3(dot(c,vec3(.4122214708,.5363325363,.0514459929)),dot(c,vec3(.2119034982,.6806995451,.1073969566)),dot(c,vec3(.0883024619,.2817188376,.6299787005))),vec3(0.)),vec3(1./3.));
  return vec3(dot(m,vec3(.2104542553,.793617785,-.0040720468)),dot(m,vec3(1.9779984951,-2.428592205,.4505937099)),dot(m,vec3(.0259040371,.7827717662,-.808675766)));}
vec3 fromLab(vec3 L){
  vec3 m=vec3(L.x+.3963377774*L.y+.2158037573*L.z,L.x-.1055613458*L.y-.0638541728*L.z,L.x-.0894841775*L.y-1.291485548*L.z);m=m*m*m;
  return gam(vec3(dot(m,vec3(4.0767416621,-3.3077115913,.2309699292)),dot(m,vec3(-1.2684380046,2.6097574011,-.3413193965)),dot(m,vec3(-.0041960863,-.7034186147,1.707614701))));}
void main(){
  vec2 p=gl_FragCoord.xy;
  vec3 bg=texture(uBgT,p/uRes).rgb+(fract(sin(dot(p+uSeed,vec2(12.9898,78.233)))*43758.5453)-.5)/170.;
  vec4 s=texelFetch(uAcc,ivec2(p),0)*uComp.z;
  vec3 col=bg;
  if(s.a>1e-4){
    vec3 ink=s.rgb/s.a;
    float w=1.-exp(-s.a*uComp.x);
    if(uLight>.5){
      // ink on paper: the paper's own tint fades out under the ink, while the ink's hue carries even where it is
      // faint (a plain mix of red ink and warm paper would turn its soft edges peach)
      vec3 B=toLab(bg),I=toLab(ink);
      col=fromLab(vec3(mix(B.x,I.x,w),B.yz*(1.-smoothstep(0.,.12,w))+I.yz*pow(w,.8)));
    }else col=bg+ink*w*(1.+uComp.y*w);
  }
  o=vec4(col,1.);
}`;

export const VERTS_PER_PARTICLE = 4 + 2 * (SEG + 1);
export const GLOW_SLOTS = NG;
const BGS = 4; // the background's resolution divisor

// Starts compiling the world's programs (world: the GLSL that defines particle()). poll() reports "pending", "ready"
// or "failed" without blocking; draw(f) renders a frame (index.js, frame()) and returns the vertex count.
export function createRenderer(gl, world) {
  const shaders = [];
  const pcs = gl.getExtension("KHR_parallel_shader_compile");
  const start = (vs, fs) => {
    const p = gl.createProgram();
    for (const [type, src] of [[gl.VERTEX_SHADER, vs], [gl.FRAGMENT_SHADER, fs]]) {
      const sh = gl.createShader(type);
      gl.shaderSource(sh, src);
      gl.compileShader(sh);
      gl.attachShader(p, sh);
      shaders.push(sh);
    }
    gl.linkProgram(p);
    return p;
  };
  const progs = {
    bg: start(FULL_VS, BG_FS),
    trail: start(TRAIL_VS(world), TRAIL_FS),
    head: start(HEAD_VS(world), HEAD_FS),
    comp: start(FULL_VS, COMP_FS),
  };
  // Without the extension, a fence after the link commands tells when the GPU process has worked through them.
  let fence = pcs ? null : gl.fenceSync(gl.SYNC_GPU_COMMANDS_COMPLETE, 0);
  gl.flush();
  const vao = gl.createVertexArray();
  // The accumulation buffer: half-float where it can be rendered to, else 8-bit with the sums scaled by a quarter.
  const floatOK = !!gl.getExtension("EXT_color_buffer_float");
  const accS = floatOK ? 1 : 0.25;
  const tex = [], fbs = [];
  let P = null, state = "pending", aw = 0, ah = 0;

  function uniforms(p) {
    const u = {};
    const n = gl.getProgramParameter(p, gl.ACTIVE_UNIFORMS);
    for (let i = 0; i < n; i++) {
      const name = gl.getActiveUniform(p, i).name;
      u[name.replace("[0]", "")] = gl.getUniformLocation(p, name);
    }
    return { p, u };
  }

  function poll() {
    if (state !== "pending") return state;
    if (pcs) {
      if (!Object.values(progs).every((p) => gl.getProgramParameter(p, pcs.COMPLETION_STATUS_KHR))) return state;
    } else if (fence) {
      if (gl.getSyncParameter(fence, gl.SYNC_STATUS) !== gl.SIGNALED) return state;
      gl.deleteSync(fence);
      fence = null;
    }
    for (const [k, p] of Object.entries(progs)) {
      if (!gl.getProgramParameter(p, gl.LINK_STATUS)) {
        console.warn(`scene: the ${k} program did not link`, gl.getProgramInfoLog(p));
        state = "failed";
        return state;
      }
    }
    P = Object.fromEntries(Object.entries(progs).map(([k, p]) => [k, uniforms(p)]));
    state = "ready";
    return state;
  }

  // The two render targets: the background (a quarter of the size, filtered) and the accumulation buffer.
  function target(i, w, h, internal, type, filter) {
    if (!tex[i]) { tex[i] = gl.createTexture(); fbs[i] = gl.createFramebuffer(); }
    gl.bindTexture(gl.TEXTURE_2D, tex[i]);
    gl.texImage2D(gl.TEXTURE_2D, 0, internal, w, h, 0, gl.RGBA, type, null);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, filter);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, filter);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.bindFramebuffer(gl.FRAMEBUFFER, fbs[i]);
    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, tex[i], 0);
  }
  function size(W, H) {
    if (W === aw && H === ah) return;
    aw = W; ah = H;
    target(0, Math.ceil(W / BGS), Math.ceil(H / BGS), gl.RGBA8, gl.UNSIGNED_BYTE, gl.LINEAR);
    target(1, W, H, floatOK ? gl.RGBA16F : gl.RGBA8, floatOK ? gl.HALF_FLOAT : gl.UNSIGNED_BYTE, gl.NEAREST);
  }

  // m: { only, n, rects (Float32Array 32), feather (Float32Array 8), veil (4), veil2 (4) }, in device pixels.
  function shade(S, m) {
    gl.uniform4f(S.u.uMask, m.only, 0, m.n, 0);
    gl.uniform4fv(S.u.uRects, m.rects);
    gl.uniform1fv(S.u.uRectF, m.feather);
    gl.uniform4fv(S.u.uVeil, m.veil);
    gl.uniform4fv(S.u.uVeil2, m.veil2);
  }

  function draw(f) {
    size(f.W, f.H);
    gl.bindVertexArray(vao);
    gl.disable(gl.BLEND);

    gl.bindFramebuffer(gl.FRAMEBUFFER, fbs[0]);
    gl.viewport(0, 0, Math.ceil(f.W / BGS), Math.ceil(f.H / BGS));
    const B = P.bg;
    gl.useProgram(B.p);
    gl.uniform1f(B.u.uPS, BGS);
    gl.uniform2f(B.u.uRes, f.W, f.H);
    gl.uniform3fv(B.u.uBg, f.bg);
    gl.uniform1f(B.u.uLight, f.light);
    gl.uniform4fv(B.u.uG, f.glows);
    gl.uniform3fv(B.u.uGC, f.glowInks);
    gl.uniform1f(B.u.uVig, f.vignette);
    shade(B, f.bgMask);
    gl.drawArrays(gl.TRIANGLES, 0, 3);

    gl.bindFramebuffer(gl.FRAMEBUFFER, fbs[1]);
    gl.viewport(0, 0, f.W, f.H);
    gl.clearColor(0, 0, 0, 0);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.ONE, gl.ONE);
    gl.blendEquation(gl.FUNC_ADD);
    let verts = 6;
    for (const v of f.views) {
      const common = (S) => {
        gl.useProgram(S.p);
        gl.uniformMatrix4fv(S.u.uVP, false, v.VP);
        if (S.u.uVPp) gl.uniformMatrix4fv(S.u.uVPp, false, v.VPp);
        gl.uniform2f(S.u.uRes, f.W, f.H);
        gl.uniform1f(S.u.uFocal, v.focal);
        gl.uniform1f(S.u.uDpr, f.dpr);
        gl.uniform4fv(S.u.uTime, v.time);
        gl.uniform4fv(S.u.uLens, v.lens);
        gl.uniform4fv(S.u.uFog, v.fog);
        gl.uniform1f(S.u.uGain, v.gain);
        gl.uniform3fv(S.u.uInk, f.inks);
        gl.uniform1f(S.u.uN, f.n);
        gl.uniform4fv(S.u.uP, v.params);
        gl.uniform1f(S.u.uAccS, accS);
        shade(S, v.mask);
      };
      common(P.trail);
      gl.uniform3fv(P.trail.u.uTrail, v.trail);
      gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 2 * (SEG + 1), f.n);
      common(P.head);
      gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, f.n);
      verts += f.n * VERTS_PER_PARTICLE;
    }

    gl.bindFramebuffer(gl.FRAMEBUFFER, null);
    gl.viewport(0, 0, f.W, f.H);
    gl.disable(gl.BLEND);
    const C = P.comp;
    gl.useProgram(C.p);
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, tex[1]);
    gl.uniform1i(C.u.uAcc, 0);
    gl.activeTexture(gl.TEXTURE1);
    gl.bindTexture(gl.TEXTURE_2D, tex[0]);
    gl.uniform1i(C.u.uBgT, 1);
    gl.activeTexture(gl.TEXTURE0);
    gl.uniform2f(C.u.uRes, f.W, f.H);
    gl.uniform1f(C.u.uLight, f.light);
    gl.uniform1f(C.u.uSeed, f.seed);
    gl.uniform3f(C.u.uComp, f.comp[0], f.comp[1], 1 / accS);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    return verts;
  }

  function dispose() {
    if (fence) gl.deleteSync(fence);
    for (const p of Object.values(progs)) gl.deleteProgram(p);
    for (const s of shaders) gl.deleteShader(s);
    for (const t of tex) gl.deleteTexture(t);
    for (const b of fbs) gl.deleteFramebuffer(b);
    gl.deleteVertexArray(vao);
  }

  return { poll, draw, dispose, composite: floatOK ? "rgba16f" : "rgba8" };
}
