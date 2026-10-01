// WebGL2 renderer for a particle scene. There are no vertex buffers: every particle is derived from gl_InstanceID in
// the vertex shader, so a frame is a few uniforms and three draw calls (background, trails, heads), whatever the
// particle count.
// - Heads are capsules from the particle's position at the shutter opening to its position now, each projected with
//   the camera of that instant, so the streak length is the true screen motion: fast camera moves streak, slow ones
//   do not. Depth of field (a thin-lens circle of confusion), a sub-pixel fade, depth fog and a near fade all come
//   from the same projected depth.
// - Trails are short ribbons through the particle's own recent positions (flow lines that taper to the tail).
// - On light themes the inks are subtracted from the paper (reverse-subtract blending), like ink; on dark ones they
//   add up like light.
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
uniform float uLight;
uniform vec3 uBg;
uniform vec3 uInk[6];
uniform float uN;
struct Pt { vec3 p; vec3 c; float a; float s; };
uvec3 pcg3(uvec3 v){v=v*1664525u+1013904223u;v.x+=v.y*v.z;v.y+=v.z*v.x;v.z+=v.x*v.y;v^=v>>16u;v.x+=v.y*v.z;v.y+=v.z*v.x;v.z+=v.x*v.y;return v;}
vec4 hash4(uint i){uvec3 a=pcg3(uvec3(i,i^0x9e3779b9u,7u));uvec3 b=pcg3(uvec3(a.z,i,0x85ebca6bu));return vec4(a.x,a.y,a.z,b.x)*(1.0/4294967296.0);}
float fogAt(float d){return smoothstep(uFog.z,uFog.w,d)*exp(-max(d-uFog.x,0.)*uFog.y);}
vec3 inkOut(vec3 c){return uLight>.5?max(uBg-c,vec3(0.)):c;}
`;

// Hidden vertices go outside the clip volume.
const CULL = "gl_Position=vec4(-9.,-9.,0.,1.);";

const HEAD_VS = (scene) => `${HEADER}
${scene}
out vec2 vQ;
out vec3 vS;
out vec3 vC;
void main(){
  uint id=uint(gl_InstanceID);
  vec4 h=hash4(id);
  Pt a=particle(id,h,uTime.x,uTime.y);
  Pt b=particle(id,h,uTime.z,uTime.w);
  vec4 c0=uVP*vec4(a.p,1.);
  vec4 c1=uVPp*vec4(b.p,1.);
  float d=c0.w;
  float al=a.a*uGain*fogAt(d);
  if(d<.05||al<.0015){${CULL}vQ=vec2(0.);vS=vec3(1.);vC=vec3(0.);return;}
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
  vec2 ctr=s0-dv*.5;
  float hl=L*.5+re;
  vec2 px=ctr+dir*cr.x*hl+nr*cr.y*re;
  vQ=vec2(cr.x*hl,cr.y*re);
  vS=vec3(L*.5,re,smoothstep(1.6*uDpr,7.*uDpr,blur));
  vC=inkOut(a.c)*al;
  gl_Position=vec4(px/uRes*2.-1.,0.,1.);
}`;

const HEAD_FS = `#version 300 es
precision highp float;
in vec2 vQ;
in vec3 vS;
in vec3 vC;
out vec4 o;
void main(){
  float q=length(vec2(max(abs(vQ.x)-vS.x,0.),vQ.y))/vS.y;
  float g=exp(-q*q*4.2);
  float disc=(1.-smoothstep(.62,1.,q))*(.8+.2*smoothstep(.3,.8,q));
  float k=mix(g,disc*.4,vS.z)*step(q,1.);
  o=vec4(vC*k,0.);
}`;

const SEG = 5; // trail segments
const TRAIL_VS = (scene) => `${HEADER}
${scene}
uniform vec3 uTrail;
out float vV;
out vec3 vC;
void main(){
  int i=gl_VertexID>>1;
  float side=float(gl_VertexID&1)*2.-1.;
  uint id=uint(gl_InstanceID);
  vec4 h=hash4(id);
  float u=float(i)/${SEG}.;
  int j=i<${SEG}?i+1:i-1;
  float uj=float(j)/${SEG}.;
  Pt a=particle(id,h,uTime.x-uTrail.x*u,uTime.y-uTrail.x*u);
  if(a.s<0.){${CULL}vV=0.;vC=vec3(0.);return;}
  Pt b=particle(id,h,uTime.x-uTrail.x*uj,uTime.y-uTrail.x*uj);
  vec4 ca=uVP*vec4(a.p,1.);
  vec4 cb=uVP*vec4(b.p,1.);
  float d=ca.w;
  float al=a.a*uGain*uTrail.z*fogAt(d);
  if(d<.05||cb.w<.05||al<.001){${CULL}vV=0.;vC=vec3(0.);return;}
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
  vC=inkOut(a.c)*al;
  gl_Position=vec4((sa+nr*side*re)/uRes*2.-1.,0.,1.);
}`;

const TRAIL_FS = `#version 300 es
precision highp float;
in float vV;
in vec3 vC;
out vec4 o;
void main(){o=vec4(vC*exp(-vV*vV*2.6),0.);}`;

// Background: the paper colour, soft glows at the scene's focal points, a vignette, and a fixed dither.
const BG_VS = `#version 300 es
void main(){vec2 p=vec2(float((gl_VertexID<<1)&2),float(gl_VertexID&2));gl_Position=vec4(p*2.-1.,0.,1.);}`;

const BG_FS = `#version 300 es
precision highp float;
uniform vec2 uRes;
uniform vec3 uBg;
uniform float uLight;
uniform vec4 uG[3];
uniform vec3 uGC[3];
uniform float uVig;
out vec4 o;
void main(){
  vec2 p=gl_FragCoord.xy;
  vec3 c=uBg;
  for(int i=0;i<3;i++){
    vec2 d=(p-uG[i].xy)/max(uG[i].z,1.);
    float k=uG[i].w*exp(-dot(d,d));
    c+=(uLight>.5?(uGC[i]-uBg):uGC[i])*k;
  }
  vec2 v=p/uRes-.5;
  v.x*=uRes.x/uRes.y;
  float vg=uVig*dot(v,v);
  c=uLight>.5?c-vec3(.035,.045,.03)*vg:c*(1.-vg);
  c+=(fract(sin(dot(p,vec2(12.9898,78.233)))*43758.5453)-.5)/170.;
  o=vec4(c,1.);
}`;

export const VERTS_PER_TRAIL = 2 * (SEG + 1);

// Starts compiling the scene's programs. poll() reports "pending", "ready" or "failed" without blocking.
export function createRenderer(gl, scene) {
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
  const progs = { bg: start(BG_VS, BG_FS), trail: start(TRAIL_VS(scene.glsl), TRAIL_FS), head: start(HEAD_VS(scene.glsl), HEAD_FS) };
  // Without the extension, a fence after the link commands tells when the GPU process has worked through them.
  let fence = pcs ? null : gl.fenceSync(gl.SYNC_GPU_COMMANDS_COMPLETE, 0);
  gl.flush();
  const vao = gl.createVertexArray();
  let P = null, state = "pending";

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
    P = { bg: uniforms(progs.bg), trail: uniforms(progs.trail), head: uniforms(progs.head) };
    state = "ready";
    return state;
  }

  // f: the frame (see index.js, frame()). Returns the vertex count drawn.
  function draw(f) {
    gl.bindVertexArray(vao);
    gl.viewport(0, 0, f.W, f.H);
    gl.disable(gl.BLEND);
    const B = P.bg;
    gl.useProgram(B.p);
    gl.uniform2f(B.u.uRes, f.W, f.H);
    gl.uniform3fv(B.u.uBg, f.bg);
    gl.uniform1f(B.u.uLight, f.light);
    gl.uniform4fv(B.u.uG, f.glows);
    gl.uniform3fv(B.u.uGC, f.glowInks);
    gl.uniform1f(B.u.uVig, f.vignette);
    gl.drawArrays(gl.TRIANGLES, 0, 3);

    gl.enable(gl.BLEND);
    gl.blendFunc(gl.ONE, gl.ONE);
    gl.blendEquation(f.light ? gl.FUNC_REVERSE_SUBTRACT : gl.FUNC_ADD);
    const common = (S) => {
      gl.useProgram(S.p);
      gl.uniformMatrix4fv(S.u.uVP, false, f.VP);
      if (S.u.uVPp) gl.uniformMatrix4fv(S.u.uVPp, false, f.VPp);
      gl.uniform2f(S.u.uRes, f.W, f.H);
      gl.uniform1f(S.u.uFocal, f.focal);
      gl.uniform1f(S.u.uDpr, f.dpr);
      gl.uniform4fv(S.u.uTime, f.time);
      gl.uniform4fv(S.u.uLens, f.lens);
      gl.uniform4fv(S.u.uFog, f.fog);
      gl.uniform1f(S.u.uGain, f.gain);
      gl.uniform1f(S.u.uLight, f.light);
      gl.uniform3fv(S.u.uBg, f.bg);
      gl.uniform3fv(S.u.uInk, f.inks);
      gl.uniform1f(S.u.uN, f.n);
    };
    common(P.trail);
    gl.uniform3fv(P.trail.u.uTrail, f.trail);
    gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, VERTS_PER_TRAIL, f.n);
    common(P.head);
    gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, f.n);
    return 3 + f.n * (4 + VERTS_PER_TRAIL);
  }

  function dispose() {
    if (fence) gl.deleteSync(fence);
    for (const p of Object.values(progs)) gl.deleteProgram(p);
    for (const s of shaders) gl.deleteShader(s);
    gl.deleteVertexArray(vao);
  }

  return { poll, draw, dispose };
}
