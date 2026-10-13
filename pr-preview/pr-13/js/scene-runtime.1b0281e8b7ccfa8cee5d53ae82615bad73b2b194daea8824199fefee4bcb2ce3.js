var Nt="bool bad(float x){return (floatBitsToUint(x)&0x7f800000u)==0x7f800000u;}",le=`#version 300 es
precision highp float;
precision highp int;
${Nt}
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
`,Gt=`
${Nt}
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
`,Ot="gl_Position=vec4(-9.,-9.,0.,1.);",We=t=>`${le}
${t}
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
  if(d<.05||al<.0015){${Ot}vQ=vec2(0.);vS=vec3(1.);vC=vec4(0.);return;}
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
  if(bad(px.x+px.y+hl+re+blur+al+a.c.x+a.c.y+a.c.z)){${Ot}vQ=vec2(0.);vS=vec3(1.);vC=vec4(0.);return;}
  vQ=vec2(cr.x*hl,cr.y*re);
  vS=vec3(L*.5,re,smoothstep(1.6*uDpr,7.*uDpr,blur));
  vC=vec4(a.c*al,al);
  gl_Position=vec4(px/uRes*2.-1.,0.,1.);
}`,He=`#version 300 es
precision highp float;
${Gt}
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
  if(bad(o.r+o.g+o.b+o.a))o=vec4(0.);
}`,lt=5,je=t=>`${le}
${t}
uniform vec3 uTrail;
out float vV;
out vec4 vC;
void main(){
  int i=gl_VertexID>>1;
  float side=float(gl_VertexID&1)*2.-1.;
  uint id=uint(gl_InstanceID);
  vec4 h=hash4(id);
  float u=float(i)/${lt}.;
  int j=i<${lt}?i+1:i-1;
  float uj=float(j)/${lt}.;
  Pt a=particle(id,h,uTime.x-uTrail.x*u,uTime.y-uTrail.x*u);
  Pt b=particle(id,h,uTime.x-uTrail.x*uj,uTime.y-uTrail.x*uj);
  vec4 ca=uVP*vec4(a.p,1.);
  vec4 cb=uVP*vec4(b.p,1.);
  float d=ca.w;
  float al=a.a*uGain*uTrail.z*fogAt(d);
  vV=0.;vC=vec4(0.);
  // A point at or behind the near plane is culled. A point that shows nothing is put on the trail's centreline, with
  // no width: a strip that shows nothing then has no area, and one that shows in part tapers to that point. (Culled,
  // it would stretch a sliver from the particle across the screen to the cull point.)
  vec2 sa=(ca.xy/ca.w*.5+.5)*uRes;
  if(!(d>=.05)||bad(sa.x+sa.y)){${Ot}return;}
  if(!(cb.w>=.05)||!(al>=.001)){gl_Position=vec4(sa/uRes*2.-1.,0.,1.);return;}
  vec2 sb=(cb.xy/cb.w*.5+.5)*uRes;
  vec2 dv=i<${lt}?sb-sa:sa-sb;
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
  vec2 px=sa+nr*side*re;
  if(bad(px.x+px.y+al+a.c.x+a.c.y+a.c.z)){gl_Position=vec4(sa/uRes*2.-1.,0.,1.);return;}
  vV=side;
  vC=vec4(a.c*al,al);
  gl_Position=vec4(px/uRes*2.-1.,0.,1.);
}`,qe=`#version 300 es
precision highp float;
${Gt}
in float vV;
in vec4 vC;
uniform float uAccS;
out vec4 o;
void main(){
  o=vC*(exp(-vV*vV*2.6)*shade(gl_FragCoord.xy)*uAccS);
  if(bad(o.r+o.g+o.b+o.a))o=vec4(0.);
}`,fe=`#version 300 es
void main(){vec2 p=vec2(float((gl_VertexID<<1)&2),float(gl_VertexID&2));gl_Position=vec4(p*2.-1.,0.,1.);}`,Tt=6,Xe=`#version 300 es
precision highp float;
${Gt}
uniform vec2 uRes;
uniform vec3 uBg;
uniform float uLight;
uniform vec4 uG[${Tt}];
uniform vec3 uGC[${Tt}];
uniform float uVig;
uniform float uPS;
out vec4 o;
void main(){
  vec2 p=gl_FragCoord.xy*uPS;
  vec3 c=uBg,gl=vec3(0.);
  for(int i=0;i<${Tt};i++){
    vec2 d=(p-uG[i].xy)/max(uG[i].z,1.);
    gl+=(uLight>.5?uGC[i]-uBg:uGC[i])*uG[i].w*exp(-dot(d,d));
  }
  c+=gl*shade(p);
  vec2 v=p/uRes-.5;
  v.x*=uRes.x/uRes.y;
  float vg=uVig*dot(v,v);
  o=vec4(uLight>.5?c-vec3(.035,.045,.03)*vg:c*(1.-vg),1.);
}`,Ze=`#version 300 es
precision highp float;
${Nt}
uniform sampler2D uAcc;
uniform sampler2D uBgT;
uniform vec2 uRes;
uniform vec2 uOut;
uniform float uLight;
uniform float uSeed;
uniform vec3 uComp;
out vec4 o;
vec3 lin(vec3 c){c=max(c,vec3(0.));return mix(c/12.92,pow((c+.055)/1.055,vec3(2.4)),step(.04045,c));}
vec3 gam(vec3 c){c=max(c,vec3(0.));return mix(c*12.92,1.055*pow(c,vec3(1./2.4))-.055,step(.0031308,c));}
vec3 toLab(vec3 c){c=lin(c);
  vec3 m=pow(max(vec3(dot(c,vec3(.4122214708,.5363325363,.0514459929)),dot(c,vec3(.2119034982,.6806995451,.1073969566)),dot(c,vec3(.0883024619,.2817188376,.6299787005))),vec3(0.)),vec3(1./3.));
  return vec3(dot(m,vec3(.2104542553,.793617785,-.0040720468)),dot(m,vec3(1.9779984951,-2.428592205,.4505937099)),dot(m,vec3(.0259040371,.7827717662,-.808675766)));}
vec3 fromLab(vec3 L){
  vec3 m=vec3(L.x+.3963377774*L.y+.2158037573*L.z,L.x-.1055613458*L.y-.0638541728*L.z,L.x-.0894841775*L.y-1.291485548*L.z);m=m*m*m;
  return gam(vec3(dot(m,vec3(4.0767416621,-3.3077115913,.2309699292)),dot(m,vec3(-1.2684380046,2.6097574011,-.3413193965)),dot(m,vec3(-.0041960863,-.7034186147,1.707614701))));}
void main(){
  vec2 p=gl_FragCoord.xy,u=p/uOut;
  vec3 bg=texture(uBgT,u).rgb+(fract(sin(dot(p+uSeed,vec2(12.9898,78.233)))*43758.5453)-.5)/170.;
  vec4 s=texture(uAcc,u)*uComp.z;
  if(bad(s.r+s.g+s.b+s.a))s=vec4(0.);
  vec3 col=bg;
  if(s.a>1e-4){
    vec3 ink=clamp(s.rgb/s.a,0.,1.);
    float w=1.-exp(-s.a*uComp.x);
    if(uLight>.5){
      // ink on paper: the paper's own tint fades out under the ink, while the ink's hue carries even where it is
      // faint (a plain mix of red ink and warm paper would turn its soft edges peach)
      vec3 B=toLab(bg),I=toLab(ink);
      col=fromLab(vec3(mix(B.x,I.x,w),B.yz*(1.-smoothstep(0.,.12,w))+I.yz*pow(w,.8)));
    }else col=bg+ink*w*(1.+uComp.y*w);
  }
  o=vec4(col,1.);
}`,Bt=4+2*(lt+1),Mt=Tt,vt=4;function Ut(t,e){let o=[],n=t.getExtension("KHR_parallel_shader_compile"),s=(i,h)=>{let k=t.createProgram();for(let[T,A]of[[t.VERTEX_SHADER,i],[t.FRAGMENT_SHADER,h]]){let S=t.createShader(T);t.shaderSource(S,A),t.compileShader(S),t.attachShader(k,S),o.push(S)}return t.linkProgram(k),k},a={bg:s(fe,Xe),trail:s(je(e),qe),head:s(We(e),He),comp:s(fe,Ze)},u=n?null:t.fenceSync(t.SYNC_GPU_COMMANDS_COMPLETE,0);t.flush();let l=t.createVertexArray(),c=!!(t.getExtension("EXT_color_buffer_float")||t.getExtension("EXT_color_buffer_half_float")),f=c?1:.25,m=[],E=[],y=null,d="pending",L=0,W=0;function U(i){let h={},k=t.getProgramParameter(i,t.ACTIVE_UNIFORMS);for(let T=0;T<k;T++){let A=t.getActiveUniform(i,T).name;h[A.replace("[0]","")]=t.getUniformLocation(i,A)}return{p:i,u:h}}function F(){if(d!=="pending")return d;if(n){if(!Object.values(a).every(i=>t.getProgramParameter(i,n.COMPLETION_STATUS_KHR)))return d}else if(u){if(t.getSyncParameter(u,t.SYNC_STATUS)!==t.SIGNALED)return d;t.deleteSync(u),u=null}for(let[i,h]of Object.entries(a))if(!t.getProgramParameter(h,t.LINK_STATUS))return console.warn(`scene: the ${i} program did not link`,t.getProgramInfoLog(h)),d="failed",d;return y=Object.fromEntries(Object.entries(a).map(([i,h])=>[i,U(h)])),d="ready",d}function v(i,h,k,T,A,S){m[i]||(m[i]=t.createTexture(),E[i]=t.createFramebuffer()),t.bindTexture(t.TEXTURE_2D,m[i]),t.texImage2D(t.TEXTURE_2D,0,T,h,k,0,t.RGBA,A,null),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_MIN_FILTER,S),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_MAG_FILTER,S),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_WRAP_S,t.CLAMP_TO_EDGE),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_WRAP_T,t.CLAMP_TO_EDGE),t.bindFramebuffer(t.FRAMEBUFFER,E[i]),t.framebufferTexture2D(t.FRAMEBUFFER,t.COLOR_ATTACHMENT0,t.TEXTURE_2D,m[i],0)}function w(i,h){i===L&&h===W||(L=i,W=h,v(0,Math.ceil(i/vt),Math.ceil(h/vt),t.RGBA8,t.UNSIGNED_BYTE,t.LINEAR),v(1,i,h,c?t.RGBA16F:t.RGBA8,c?t.HALF_FLOAT:t.UNSIGNED_BYTE,t.LINEAR),c&&t.checkFramebufferStatus(t.FRAMEBUFFER)!==t.FRAMEBUFFER_COMPLETE&&(c=!1,f=.25,v(1,i,h,t.RGBA8,t.UNSIGNED_BYTE,t.LINEAR)))}function b(i,h){t.uniform4f(i.u.uMask,h.only,0,h.n,0),t.uniform4fv(i.u.uRects,h.rects),t.uniform1fv(i.u.uRectF,h.feather),t.uniform4fv(i.u.uVeil,h.veil),t.uniform4fv(i.u.uVeil2,h.veil2)}function g(i){w(i.W,i.H),t.bindVertexArray(l),t.disable(t.BLEND),t.bindFramebuffer(t.FRAMEBUFFER,E[0]),t.viewport(0,0,Math.ceil(i.W/vt),Math.ceil(i.H/vt));let h=y.bg;t.useProgram(h.p),t.uniform1f(h.u.uPS,vt),t.uniform2f(h.u.uRes,i.W,i.H),t.uniform3fv(h.u.uBg,i.bg),t.uniform1f(h.u.uLight,i.light),t.uniform4fv(h.u.uG,i.glows),t.uniform3fv(h.u.uGC,i.glowInks),t.uniform1f(h.u.uVig,i.vignette),b(h,i.bgMask),t.drawArrays(t.TRIANGLES,0,3),t.bindFramebuffer(t.FRAMEBUFFER,E[1]),t.viewport(0,0,i.W,i.H),t.clearColor(0,0,0,0),t.clear(t.COLOR_BUFFER_BIT),t.enable(t.BLEND),t.blendFunc(t.ONE,t.ONE),t.blendEquation(t.FUNC_ADD),t.enable(t.SCISSOR_TEST);let k=6;for(let A of i.views){let S=A.mask.box;if(S[2]<=0||S[3]<=0)continue;t.scissor(S[0],S[1],S[2],S[3]);let O=R=>{t.useProgram(R.p),t.uniformMatrix4fv(R.u.uVP,!1,A.VP),R.u.uVPp&&t.uniformMatrix4fv(R.u.uVPp,!1,A.VPp),t.uniform2f(R.u.uRes,i.W,i.H),t.uniform1f(R.u.uFocal,A.focal),t.uniform1f(R.u.uDpr,i.dpr),t.uniform4fv(R.u.uTime,A.time),t.uniform4fv(R.u.uLens,A.lens),t.uniform4fv(R.u.uFog,A.fog),t.uniform1f(R.u.uGain,A.gain),t.uniform3fv(R.u.uInk,i.inks),t.uniform1f(R.u.uN,i.n),t.uniform4fv(R.u.uP,A.params),t.uniform1f(R.u.uAccS,f),b(R,A.mask)};O(y.trail),t.uniform3fv(y.trail.u.uTrail,A.trail),t.drawArraysInstanced(t.TRIANGLE_STRIP,0,2*(lt+1),i.n),O(y.head),t.drawArraysInstanced(t.TRIANGLE_STRIP,0,4,i.n),k+=i.n*Bt}t.disable(t.SCISSOR_TEST),t.bindFramebuffer(t.FRAMEBUFFER,null),t.viewport(0,0,i.OW,i.OH),t.disable(t.BLEND);let T=y.comp;return t.useProgram(T.p),t.activeTexture(t.TEXTURE0),t.bindTexture(t.TEXTURE_2D,m[1]),t.uniform1i(T.u.uAcc,0),t.activeTexture(t.TEXTURE1),t.bindTexture(t.TEXTURE_2D,m[0]),t.uniform1i(T.u.uBgT,1),t.activeTexture(t.TEXTURE0),t.uniform2f(T.u.uOut,i.OW,i.OH),t.uniform1f(T.u.uLight,i.light),t.uniform1f(T.u.uSeed,i.seed),t.uniform3f(T.u.uComp,i.comp[0],i.comp[1],1/f),t.drawArrays(t.TRIANGLES,0,3),k}function V(){u&&t.deleteSync(u);for(let i of Object.values(a))t.deleteProgram(i);for(let i of o)t.deleteShader(i);for(let i of m)t.deleteTexture(i);for(let i of E)t.deleteFramebuffer(i);t.deleteVertexArray(l)}return{poll:F,draw:g,dispose:V,get composite(){return c?"rgba16f":"rgba8"}}}var I=(t,e,o)=>Math.min(o,Math.max(e,t)),D=(t,e,o)=>t+(e-t)*o,tt=(t,e,o)=>{let n=I((o-t)/(e-t),0,1);return n*n*(3-2*n)},pe=t=>1-Math.pow(1-I(t,0,1),3),Ye=(t,e)=>[t[0]-e[0],t[1]-e[1],t[2]-e[2]],gt=(t,e)=>t[0]*e[0]+t[1]*e[1]+t[2]*e[2],me=(t,e)=>[t[1]*e[2]-t[2]*e[1],t[2]*e[0]-t[0]*e[2],t[0]*e[1]-t[1]*e[0]],he=t=>{let e=Math.hypot(t[0],t[1],t[2])||1;return[t[0]/e,t[1]/e,t[2]/e]};function ve(t,e,o=0){let n=he(Ye(e,t)),s=me(n,[0,1,0]);s=Math.hypot(s[0],s[1],s[2])<1e-4?[1,0,0]:he(s);let a=me(s,n);if(o){let u=Math.cos(o),l=Math.sin(o),c=[0,1,2].map(f=>s[f]*u+a[f]*l);a=[0,1,2].map(f=>a[f]*u-s[f]*l),s=c}return{r:s,u:a,f:n}}function Wt(t,e,o,n=.05,s=400){let{r:a,u,f:l}=ve(e.pos,e.tgt,e.roll||0),c=e.pos,f=1/Math.tan(e.fov*Math.PI/360),[m,E]=e.shift||[0,0],y=f/o,d=-(s+n)/(s-n),L=-2*s*n/(s-n),W=[l[0],l[1],l[2],-gt(l,c)],U=[[y*a[0],y*a[1],y*a[2],-y*gt(a,c)],[f*u[0],f*u[1],f*u[2],-f*gt(u,c)],[-d*l[0],-d*l[1],-d*l[2],d*gt(l,c)+L],W];for(let F=0;F<4;F++)U[0][F]+=m*W[F],U[1][F]+=E*W[F];for(let F=0;F<4;F++)for(let v=0;v<4;v++)t[F*4+v]=U[v][F];return t}function de(t,e,o,n){let s=t[0]*e[0]+t[4]*e[1]+t[8]*e[2]+t[12],a=t[1]*e[0]+t[5]*e[1]+t[9]*e[2]+t[13],u=t[3]*e[0]+t[7]*e[1]+t[11]*e[2]+t[15];return u<=.01?null:[(s/u*.5+.5)*o,(a/u*.5+.5)*n,u]}function Ke(t,e){let o=t.length,n=[],s=new Array(o).fill(0);for(let a=0;a<o-1;a++)n[a]=(e[a+1]-e[a])/(t[a+1]-t[a]);for(let a=1;a<o-1;a++)s[a]=n[a-1]*n[a]<=0?0:2*n[a-1]*n[a]/(n[a-1]+n[a]);return a=>{if(a<=t[0])return e[0];if(a>=t[o-1])return e[o-1];let u=0;for(;a>t[u+1];)u++;let l=t[u+1]-t[u],c=(a-t[u])/l,f=c*c,m=f*c;return(2*m-3*f+1)*e[u]+(m-2*f+c)*l*s[u]+(-2*m+3*f)*e[u+1]+(m-f)*l*s[u+1]}}var $t=(t,e,o,n,s)=>.5*(2*e+(-t+o)*s+(2*t-5*e+4*o-n)*s*s+(-t+3*e-3*o+n)*s*s*s),Qe=["roll","fov","focus","ap","blur","exp"];function Ht(t){let e=t.length,o=Ke(t.map(n=>n.t),t.map((n,s)=>s));return(n,s)=>{let a=o(n),u=Math.min(e-2,Math.max(0,Math.floor(a))),l=a-u,c=t[Math.max(0,u-1)],f=t[u],m=t[u+1],E=t[Math.min(e-1,u+2)];s.pos=[0,1,2].map(d=>$t(c.pos[d],f.pos[d],m.pos[d],E.pos[d],l)),s.tgt=[0,1,2].map(d=>$t(c.tgt[d],f.tgt[d],m.tgt[d],E.tgt[d],l));for(let d of Qe)s[d]=$t(c[d],f[d],m[d],E[d],l);let y=l*l*(3-2*l);return s.shift=[D(f.shift[0],m.shift[0],y),D(f.shift[1],m.shift[1],y)],s}}function xe(t,e,o){return t.map((n,s)=>{let a=e[s],u={t:n.t};for(let l of Object.keys(n)){if(l==="t")continue;let c=n[l],f=a[l];u[l]=Array.isArray(c)?c.map((m,E)=>D(m,f[E],o)):D(c,f,o)}return u})}function jt(t,e,o,n,s=.25){let{r:a,u,f:l}=ve(t.pos,t.tgt,t.roll||0);for(let c=0;c<3;c++){let f=a[c]*e+u[c]*o+l[c]*n;t.pos[c]+=f,t.tgt[c]+=f*s}return t}var Y={w:.55,twist:.12,flow:.3,radius:1.25,length:46},qt={z:-4.3,narrow:-1.5,half:1.4},mt={a:-2,b:3.5,enter:9,leave:-5,narrow:{enter:6,leave:-5}},ye=(t,e)=>{let o=e?mt.narrow:mt;return D(o.enter,o.leave,t)},be=(t,e)=>tt(mt.a,mt.b,t-e),q=t=>t.toFixed(4),Je=`
const float ZT=44.,ZL=88.;
const float SW=${q(Y.w)},ST=${q(Y.twist)},SV=${q(Y.flow)},SA=${q(Y.radius)},SL=${q(Y.length)};
const float FZ=${q(qt.z)},FN=${q(qt.narrow)},FH=${q(qt.half)};
const float ZA=${q(mt.a)},ZB=${q(mt.b)};
// 1 below a, 0 above b (smoothstep with its edges reversed is undefined in GLSL, and some drivers take that literally)
float fall(float a,float b,float x){return 1.-smoothstep(a,b,x);}
float twist(float z){return z<0.?1.2*z:1.6*(1.-exp(-z/3.));}
// The fuse point at time t: it drifts on two slow sines that never quite repeat (less on narrow layouts).
float fuseZ(float t){return mix(FZ,FN,uP.w)+mix(1.,.6,uP.w)*(.9*sin(.23*t)+.5*sin(.37*t+1.3));}
// Strand k's centreline at z, its width w, its spread S (0 the tight braid .. 1 far upstream), how far it has fused
// (m: 0 two strands .. 1 one cord) and the tangle around the fuse point (g: 1 at it).
vec3 ctr(float z,float k,float t,out float w,out float S,out float m,out float g){
  S=pow(max(smoothstep(-1.,26.,z),1e-12),.6);
  float zf=fuseZ(t),dz=(z-zf)/2.6;
  m=fall(zf-FH,zf+FH,z);
  g=exp(-dz*dz);
  float R=mix(.2,6.4,S)*(1.-m);
  float th=twist(z)-1.28+k*3.14159265+g*(.75*sin(.7*t+.6*z)+.35*sin(.43*t-.9*z+k));
  vec2 c=vec2(cos(th),sin(th)*mix(1.,.38,S))*R;
  c+=vec2(1.4*sin(.09*z+.3),.8*sin(.06*z+1.4))*S*S;
  c+=g*.09*vec2(sin(.9*z+.8*t+k*2.4),cos(.7*z-.6*t+k*1.3));
  w=mix(.11,1.85,S)*(1.+.35*m);
  return vec3(c,z);
}
Pt braid(uint id,vec4 h,float t){
  Pt o;
  float f=float(id)/uN;
  if(f<.8){
    float k=float(id&1u);
    float z=ZT-mod(h.x*ZL+(1.2+1.1*h.y)*t,ZL);
    float w,S,m,g;
    vec3 c=ctr(z,k,t,w,S,m,g);
    float halo=step(.78,fract(h.z*7.31));
    float rr=w*sqrt(max(-log(1.-.96*h.z),0.))*.5*(1.+1.5*halo)*(1.+.6*g);
    float ph=6.2832*h.w+1.7*z*(1.-.65*S);
    o.p=c+vec3(cos(ph),sin(ph),0.)*rr;
    vec3 base=k<.5?mix(uInk[0],uInk[1],h.y*h.y*.8):mix(uInk[2],uInk[3],h.y*.9);
    o.c=mix(base,uInk[4],max(.5*fall(-2.5,5.,z)*(h.y<.22?.4:1.),m));
    float core=exp(-rr*rr/(w*w)*1.6);
    o.a=(.28+.72*core)*(1.-.55*halo)*(1.+.9*exp(-z*z/5.))*mix(.42,1.,S)*smoothstep(-44.,-34.,z)*fall(32.,44.,z);
    o.s=.019*(.7+.6*h.z);
  }else if(f<.875){
    float r=2.9*sqrt(max(-log(1.-.985*h.x),0.))*.62;
    float a=6.2832*h.y+t*(.14+.38/(.6+r));
    float z=(h.z-.5)*.34-.2+.12*sin(r*2.3-t*.8);
    o.p=vec3(cos(a)*r,sin(a)*r*.86,z);
    o.c=mix(uInk[4],uInk[1],h.w*h.w*.45);
    o.a=.46*exp(-r*.42)*(.6+.4*h.w);
    o.s=.018;
  }else{
    float z=ZT-mod(h.z*ZL+.45*t,ZL);
    o.p=vec3((h.x-.5)*36.,(h.y-.5)*22.,z);
    o.p.xy+=.5*sin(vec2(.21,.17)*z+t*.1+h.w*6.);
    o.c=mix(uInk[5],uInk[4],h.w*h.w);
    o.a=.2*smoothstep(-44.,-36.,z)*fall(36.,44.,z);
    o.s=.017;
  }
  return o;
}
// 0 where the strands run apart, 1 where they have zipped into one (zipAt in JS)
float zip(float x){return smoothstep(ZA,ZB,x-uP.w);}
Pt strands(uint id,vec4 h,float t){
  Pt o;
  float f=float(id)/uN;
  float k=float(id&1u);
  if(f<.86){
    float x=(fract(h.x+t*SV*(.8+.4*h.y)/SL)-.5)*SL;
    float ph=SW*x-ST*t+k*3.14159265;
    float m=zip(x);
    // joined, the helix narrows to a thin twist and the fibres draw in: one rope
    float A=SA*mix(1.,.16,m);
    float rr=.6*mix(1.,.62,m)*sqrt(max(-log(1.-.97*h.z),0.));
    float a=6.2832*h.w+1.3*x-.2*t;
    o.p=vec3(x,A*sin(ph),.9*A*cos(ph))+vec3(0.,cos(a),sin(a))*rr;
    vec3 base=k<.5?mix(uInk[0],uInk[1],h.y*.6):mix(uInk[2],uInk[3],h.y*.7);
    float s=sin(ph);
    o.c=mix(base,uInk[4],max(.88*exp(-s*s/.2)*(1.-m),.94*smoothstep(.15,.85,m)));
    o.a=.5*(.3+.7*exp(-rr*rr*2.4))*fall(SL*.5-5.,SL*.5,abs(x));
    o.s=.019*(.7+.6*h.z);
  }else if(f<.93){
    float S=3.14159265/SW;
    float x=mod(floor(h.x*8.)*S+ST*t/SW+SL*.5,8.*S)-SL*.5;
    vec3 r=vec3(h.y,h.z,fract(h.w*7.3))-.5;
    o.p=vec3(x,0.,0.)+normalize(r+1e-3)*.75*sqrt(max(-log(1.-.95*fract(h.w*3.7)),0.));
    o.c=mix(uInk[4],k<.5?uInk[0]:uInk[2],.15*h.y);
    o.a=.36*exp(-dot(o.p.yz,o.p.yz)*.6)*fall(SL*.5-5.,SL*.5,abs(x))*(1.-zip(x));
    o.s=.018;
  }else{
    float x=(fract(h.x+t*SV*.5/SL)-.5)*SL;
    o.p=vec3(x,(h.y-.5)*7.,(h.z-.5)*7.);
    o.c=mix(uInk[5],uInk[4],h.w*h.w);
    o.a=.13*fall(SL*.5-5.,SL*.5,abs(x));
    o.s=.017;
  }
  return o;
}
Pt particle(uint id,vec4 h,float t,float it){
  if(uP.z>.5)return strands(id,h,t);
  Pt o=braid(id,h,t);
  float t0=.02+.9*clamp(length(o.p)/26.,0.,1.)+.25*fract(h.w*5.17);
  float a=clamp((it-t0)/.75,0.,1.);
  if(a<1.){
    float e=1.-(1.-a)*(1.-a)*(1.-a);
    vec3 r=vec3(h.x,h.y,fract(h.z*3.1))-.5;
    o.p=mix(o.p+normalize(r+1e-3)*(4.+7.*fract(h.z*7.3)),o.p,e);
    o.a*=a*a*(3.-2.*a);
  }
  return o;
}`,Zt=3,Xt=[{t:0,pos:[2.2,1,-26],tgt:[.4,.2,-4],roll:.06,fov:42,focus:18,ap:1.6,blur:18,exp:.95,shift:[.1,0]},{t:.3,pos:[2.3,1,-26.8],tgt:[.4,.2,-4.4],roll:.065,fov:41.6,focus:18,ap:1.6,blur:18,exp:1,shift:[.1,0]},{t:1.3,pos:[3.4,1.6,-13],tgt:[.2,.1,0],roll:.1,fov:42,focus:10,ap:2,blur:18,exp:1,shift:[.15,0]},{t:2.1,pos:[6,4,-9.6],tgt:[0,0,-.2],roll:.03,fov:40,focus:11,ap:3.5,blur:22,exp:1,shift:[.24,.03]},{t:2.6,pos:[7.6,5.15,-11.6],tgt:[0,0,-.5],roll:-.004,fov:39.6,focus:13.5,ap:4.2,blur:26,exp:1,shift:[.26,.03]},{t:3,pos:[7.4,5,-11.3],tgt:[0,0,-.5],roll:0,fov:40,focus:13.5,ap:4.2,blur:26,exp:1,shift:[.26,.03]}],we=[{t:0,pos:[1.4,.8,-27],tgt:[.2,.3,0],roll:.05,fov:56,focus:20,ap:1.6,blur:18,exp:.95,shift:[0,0]},{t:.3,pos:[1.45,.8,-27.8],tgt:[.2,.3,0],roll:.055,fov:55.6,focus:20,ap:1.6,blur:18,exp:1,shift:[0,0]},{t:1.3,pos:[1.8,1.4,-15.5],tgt:[0,.3,2],roll:.08,fov:57,focus:12,ap:2,blur:18,exp:1,shift:[0,0]},{t:2.1,pos:[.9,3,-12.8],tgt:[0,.5,3.6],roll:.02,fov:58,focus:12,ap:3.4,blur:22,exp:1,shift:[0,0]},{t:2.6,pos:[.45,3.6,-12],tgt:[0,.5,4],roll:-.004,fov:58,focus:13,ap:4,blur:24,exp:1,shift:[0,0]},{t:3,pos:[.5,3.5,-12.2],tgt:[0,.5,4],roll:0,fov:58,focus:13,ap:4,blur:24,exp:1,shift:[0,0]}];function to(t,e,o){let n=tt(Zt,Zt+2.2,e);return n>0&&jt(t,Math.sin(o*.13)*.32*n,Math.sin(o*.09+1.2)*.16*n,Math.sin(o*.071)*.22*n,.15),t}var eo=[{p:[0,0,0],r:.2,a:{dark:.18,light:.12},ink:4},{p:[4.5,.5,16],r:.32,a:{dark:.05,light:.035},ink:0},{p:[-4.5,-.5,16],r:.32,a:{dark:.05,light:.035},ink:2}],oo=t=>({y:.04*t,s:1+.05*t});function Se(){let t=Ht(Xt);return{N:26e3,T:Zt,glsl:Je,gain:{dark:.95,light:.9},composite:{dark:[2.6,.35],light:[2.4,0]},trail:{time:.3,width:.75,alpha:{dark:.55,light:.5}},vignette:{dark:.55,light:.3},fog:[9,.042,.9,2.6],layout(e){t=Ht(e<=0?Xt:e>=1?we:xe(Xt,we,e))},glows(e){let o=tt(.15,1.7,e);return eo.map(n=>({...n,a:{dark:n.a.dark*o,light:n.a.light*o}}))},pose(e,o,n,s){return t(o,e),jt(e,s[0]*.6,s[1]*.32,0,.18),to(e,o,n)}}}var Lo=window.matchMedia("(prefers-reduced-motion: reduce)");function dt(t,e,o,n){let s=t.x-e,a=Math.exp(-o*n),u=t.v+o*s;return t.x=e+(s+u*n)*a,t.v=(t.v-o*u*n)*a,Math.abs(t.x-e)+Math.abs(t.v)*.05}var Ee="scene-quality",no=2560*1600,Yt=[1,1,.5,.25,.125,.0625,.03125,.03125],ro=[1,1,1,.85,.75,.65,.55,.4],K=8,ao=t=>Math.min(2.8,(1/Yt[t])**.3),io=t=>Math.min(2.6,(1/Yt[t])**.32),Le=2,so=45,co=420,At=1/30,Te=12,uo=["red","red-2","blue","blue-2","purple","dust"],fo=new Set(["Shift","Control","Alt","Meta","CapsLock","Fn","OS"]),Me=t=>{try{return t(sessionStorage)}catch{return null}},xt=t=>{try{performance.mark("scene:"+t)}catch{}};function lo(t){let e=String(t||"").trim(),o=/^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(e);if(o){let n=o[1].length===3?o[1].replace(/./g,"$&$&"):o[1];return[0,2,4].map(s=>parseInt(n.slice(s,s+2),16)/255)}return o=/^rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)/i.exec(e),o?[o[1],o[2],o[3]].map(n=>I(parseFloat(n)/255,0,1)):null}function mo(t){let e=t.getExtension("WEBGL_debug_renderer_info"),o=e?t.getParameter(e.UNMASKED_RENDERER_WEBGL):"";return/swiftshader|llvmpipe|softpipe|software|basic render/i.test(String(o))}var ge=()=>({only:0,n:0,rects:new Float32Array(32),feather:new Float32Array(8),veil:new Float32Array(4),veil2:new Float32Array(4),box:new Int32Array(4)});function Ae(t,e,o,n,s,a){t.rects.fill(0),t.feather.fill(0),t.only=e?1:0,t.n=e?Math.min(8,e.length):0;let u=e?s:0,l=e?a:0,c=e?0:s,f=e?0:a;for(let E=0;E<t.n;E++){let y=e[E],d=[y.x0*n,a-y.y1*n,y.x1*n,a-y.y0*n];t.rects.set(d,E*4),t.feather[E]=(y.f??120)*n,u=Math.min(u,d[0]),l=Math.min(l,d[1]),c=Math.max(c,d[2]),f=Math.max(f,d[3])}u=I(Math.floor(u),0,s),l=I(Math.floor(l),0,a),t.box.set([u,l,Math.max(0,I(Math.ceil(c),0,s)-u),Math.max(0,I(Math.ceil(f),0,a)-l)]);let m=o||{};t.veil.set([(m.colX??0)*n,m.colS??0,a-(m.bottomY??0)*n,m.bottomS??0]),t.veil2.set([(m.topH??0)*n,m.topS??0,(m.f??160)*n,a])}function ho(t,e={}){let o=document.createElement("canvas");o.setAttribute("aria-hidden","true");let n=o.getContext("webgl2",{alpha:!1,antialias:!1,depth:!1,stencil:!1,premultipliedAlpha:!0,preserveDrawingBuffer:!1,powerPreference:"high-performance"});if(!n)return null;let s=Me(r=>r.getItem(Ee));if(s===null&&mo(n))return n.getExtension("WEBGL_lose_context")?.loseContext(),null;let a=Se(),u=a.T,l=u+2.2,c=e.reduced||window.matchMedia("(prefers-reduced-motion: reduce)"),f=Ut(n,a.glsl),m=!1,E=!1,y=!1,d=!1,L=I(Math.round(+s||0),0,K),W=!1,U=1,F=1,v=1,w=1,b=1,g=1,V=1,i=1,h=0,k=1,T=0,A=null,S=0,O=0,R=!1,N=!1,et=Te,C=e.intro&&!c.matches?0:l,j=null,ot=!1,wt=C<u,M={x:{x:0,v:0},y:{x:0,v:0},tx:0,ty:0},nt={x:1,v:0,t:1},ht={x:1,v:0,t:1},P={W:v,H:w,OW:U,OH:F,dpr:b,light:0,n:0,vignette:.5,seed:0,comp:[1,0],bg:new Float32Array(3),inks:new Float32Array(18),glows:new Float32Array(Mt*4),glowInks:new Float32Array(Mt*3),bgMask:ge(),views:[]},Kt=[],_e=r=>Kt[r]||(Kt[r]={VP:new Float32Array(16),VPp:new Float32Array(16),focal:1,gain:1,time:new Float32Array(4),lens:new Float32Array(4),fog:new Float32Array(4),trail:new Float32Array(3),params:new Float32Array(4),mask:ge()}),Q="dark",Rt=[],X={frames:0,js:[],level:L,vertices:0},Qt=[],J=(r,p,x,_)=>{r.addEventListener(p,x,_),Qt.push([r,p,x,_])},yt=()=>C<u,kt=()=>Math.max(64,Math.round(a.N*Yt[Math.min(L,K-1)]));function _t(){let r=getComputedStyle(t),p=(_,H)=>lo(r.getPropertyValue(_))||H,x=r.getPropertyValue("--scene-ink").trim()==="ink";Q=x?"light":"dark",P.light=x?1:0,P.bg.set(p("--scene-bg",x?[1,.988,.941]:[.063,.059,.059])),uo.forEach((_,H)=>P.inks.set(p(`--scene-${_}`,[.55,.5,.75]),H*3))}function bt(){let r=t.getBoundingClientRect();h=Math.max(0,-parseFloat(getComputedStyle(t).marginTop)||0),k=Math.max(1,r.height-2*h),T=document.body.offsetHeight;let p=window.devicePixelRatio||1,x=L>=1?Math.min(1,p):Math.min(2,p);x=Math.min(x,Math.sqrt(no/Math.max(1,r.width*k)));let _=Math.max(1,Math.round(r.width*x)),H=Math.max(1,Math.round(r.height*x)),Et=ro[Math.min(L,K-1)],ct=Math.max(1,Math.round(_*Et)),ut=Math.max(1,Math.round(H*Et));return g=Math.max(1,r.width),V=Math.max(1,r.height),i=g/V,ct===v&&ut===w&&_===U&&H===F?!1:(U=_,F=H,v=ct,w=ut,b=v/g,o.width=U,o.height=F,a.layout(1-tt(.62,1.25,g/k)),!0)}function Fe(r){let p=Math.max(-h,Math.min(r-h,T-V)),x=Math.round((p+h)*100)/100;return x!==A&&(A=x,t.style.transform=`translate3d(0,${x}px,0)`),x-h}function Jt(r,p){let x=V/p.h;r.fov=2*Math.atan(Math.tan(r.fov*Math.PI/360)*x)*180/Math.PI;let _=r.shift||[0,0];r.shift=[_[0],1-(2*p.y+p.h)/V+_[1]/x]}function Pe(){let r=C,p=et,x=[M.x.x,M.y.x],_=window.scrollY,H=Fe(_),Et={it:r,ft:p,T:u,W:g,H:V,top:H,vh:k,sy:_,theme:Q},ct=e.views?e.views(Et):[{id:"hero"}],ut=1-nt.x,Ge=I(ht.x,0,1),Be=kt();P.W=v,P.H=w,P.OW=U,P.OH=F,P.dpr=b,P.n=Be,P.vignette=(e.vignette?e.vignette(Q,k):a.vignette[Q])*(V/k)**2,P.comp=a.composite[Q],P.seed=p*60%97,P.glows.fill(0),P.views.length=0;let Lt=0;Rt=[],ct.forEach(($,$e)=>{let G=_e($e),B=$.pose,ft=$.pose;if(!B){B=a.pose({},r,p,x),ft=a.pose({},r-At,p-At,x);let z=$.box||{y:_-H,h:k};Jt(B,z),Jt(ft,z)}for(let z of B===ft?[B]:[B,ft])z.focus=D(z.focus,1.6,ut),z.ap=D(z.ap,7,ut),z.blur=D(z.blur,15,ut);Wt(G.VP,B,i),ft===B?G.VPp.set(G.VP):Wt(G.VPp,ft,i);let ue=(B.exp??1)*Ge,Ct=$.trail||a.trail;G.focal=.5*w/Math.tan(B.fov*Math.PI/360),G.gain=a.gain[Q]*ue*io(Math.min(L,K-1)),G.time.set([p,r,p-At,r-At]),G.lens.set([B.focus,B.ap*b,B.blur*b,b*ao(Math.min(L,K-1))]),G.fog.set(a.fog),G.trail.set([Ct.time,Ct.width,Ct.alpha[Q]]),G.params.set([0,0,$.form||0,$.param||0]),Ae(G.mask,$.rect?[$.rect]:null,$.veil,b,v,w),P.views.push(G);for(let z of $.glows||a.glows(r)){let Dt=Lt<Mt&&de(G.VP,z.p,v,w);Dt&&(P.glows.set([Dt[0],Dt[1],z.r*w*(k/V),z.a[Q]*ue],Lt*4),P.glowInks.set(P.inks.subarray(z.ink*3,z.ink*3+3),Lt*3),Lt++)}Rt.push({id:$.id??null,pos:B.pos.map(z=>Math.round(z*1e3)/1e3)})});let Ue=ct.map($=>$.rect).filter(Boolean);return Ae(P.bgMask,e.views?Ue:null,ct[0]?.veil,b,v,w),{it:r,T:u}}function it(){if(!m||y)return 0;let r=performance.now(),p=Pe();X.vertices=f.draw(P),d||(d=!0,t.append(o),xt(yt()?"first-frame:intro":"first-frame"),requestAnimationFrame(()=>{!y&&!E&&t.classList.add("is-shown")})),e.onFrame?.(p);let x=performance.now()-r;return X.frames++,X.js.push(x),X.js.length>600&&X.js.shift(),x}function te(r){wt&&(wt=!1,xt("intro-end:"+r),e.onIntroEnd?.(r))}function ze(){yt()&&te("stopped"),C=Math.max(C,l),j=null;for(let r of[nt,ht])r.x=r.t,r.v=0;c.matches&&(M.tx=M.ty=0),M.x.x=M.tx,M.y.x=M.ty,M.x.v=M.y.v=0}function rt(){!m||y||(ze(),it())}let at=()=>m&&!y&&!R&&!W&&!c.matches&&L<K,Ie=()=>e.visible?e.visible(h):!0,ee=()=>at()&&!document.hidden&&Ie(),pt=[],oe=0;function Ve(r){if(L>=K-1||oe++<Le||r>1e3||(pt.push(r),pt.length<(oe<=Le+8?4:20)))return;let p=pt.slice().sort((_,H)=>_-H)[pt.length>>1];if(pt.length=0,p<=so)return;let x=L===0&&(window.devicePixelRatio||1)<=1?1:L;L=Math.min(K-1,Math.max(L+1,x+Math.max(1,Math.ceil(Math.log2(p/28))))),X.level=L,Me(_=>_.setItem(Ee,String(L))),xt(`quality:${L}:${Math.round(p)}ms`),bt(),e.onQuality?.(L)}function Ce(r){if(!(C>=l)){if(j){let p=pe((performance.now()-j.at)/co);C=D(j.from,u,p),p>=1&&(j=null)}else C=Math.min(l,C+r);C>=u&&te(ot?"skipped":"played")}}function ne(r){if(S=0,!ee()){O=0,at()&&!document.hidden&&!N&&(N=!0,it());return}N=!1;let p=O?r-O:0,x=O?Math.min(.25,p/1e3):1/60;O=r,Ce(x),et+=Math.min(.05,x),dt(nt,nt.t,6,x),dt(ht,ht.t,6,x),dt(M.x,M.tx,3.2,x),dt(M.y,M.ty,3.2,x),it(),p&&Ve(p),ee()&&(S=requestAnimationFrame(ne))}let Z=()=>{!S&&m&&at()&&!document.hidden&&(S=requestAnimationFrame(ne))},st=()=>{S&&cancelAnimationFrame(S),S=0,O=0},Ft=()=>at()?Z():rt(),St=0,De=()=>{St||(St=requestAnimationFrame(()=>{St=0,rt()}))},re=()=>{yt()&&!j&&(j={from:C,at:performance.now()},ot=!0,xt("intro-skip"))},Pt=0;function zt(){if(Pt=0,y)return;let r=f.poll();if(r==="pending"){Pt=requestAnimationFrame(zt);return}if(r==="failed"){ae("shaders");return}m=!0,xt("ready"),_t(),bt(),t.classList.add("is-live"),e.onQuality?.(L),at()?(it(),Z()):rt(),e.onReady?.()}function ae(r){E=!0,m=!1,st(),t.classList.remove("is-live","is-shown"),e.onFail?.(r)}_t(),zt();let Oe=r=>{(r.type!=="keydown"||!fo.has(r.key))&&re()},Ne=requestAnimationFrame(()=>{if(!y)for(let r of["keydown","pointerdown","wheel","touchstart"])J(window,r,Oe,{passive:!0})}),ie=(r,p)=>{c.matches||(M.tx=I(r/window.innerWidth*2-1,-1,1),M.ty=I(-(p/window.innerHeight*2-1),-1,1),Z())},se=()=>{M.tx=0,M.ty=0,Z()};J(window,"pointermove",r=>{r.pointerType!=="touch"&&ie(r.clientX,r.clientY)},{passive:!0}),J(window,"touchmove",r=>{let p=r.touches[0];p&&ie(p.clientX,p.clientY)},{passive:!0}),J(window,"touchend",se,{passive:!0}),J(document,"pointerleave",se),J(document,"visibilitychange",()=>document.hidden?st():Z());let ce=()=>c.matches?(st(),rt()):Z();c.addEventListener("change",ce);let It=0,Vt=new ResizeObserver(()=>{clearTimeout(It),It=setTimeout(()=>{if(!m)return;let r=T;!bt()&&T===r||(at()?S||(it(),Z()):rt())},60)});return Vt.observe(t),Vt.observe(document.body),J(o,"webglcontextlost",r=>{r.preventDefault(),ae("context lost")}),J(o,"webglcontextrestored",()=>{y||(f=Ut(n,a.glsl),E=!1,zt())}),{setScroll(r){(+r||0)*window.innerHeight>8&&re(),at()?Z():m&&De()},setFocus(r){nt.t=I(+r,0,1),Ft()},setIntensity(r){ht.t=I(+r,0,1),Ft()},pause(){W=!0,st(),rt()},resume(){W=!1,Ft()},restyle(){_t(),S||rt()},destroy(){y=!0,st(),cancelAnimationFrame(Pt),cancelAnimationFrame(Ne),cancelAnimationFrame(St),clearTimeout(It);for(let[r,p,x,_]of Qt)r.removeEventListener(p,x,_);c.removeEventListener("change",ce),Vt.disconnect(),f.dispose(),n.getExtension("WEBGL_lose_context")?.loseContext(),o.remove(),t.classList.remove("is-live","is-shown")},get failed(){return E},get level(){return L},seek(r,p={}){if(!m)return!1;st(),R=!0,C=Math.min(Math.max(0,r),l),et=Te+r,j=null;let x=p.ptr||[0,0];return M.x.x=M.tx=x[0],M.y.x=M.ty=x[1],M.x.v=M.y.v=0,bt(),it(),!0},live(){R=!1,Z()},clock:()=>({introT:C,flowT:et,introRunning:yt(),level:L,density:kt()/a.N,frames:X.frames,views:Rt}),stats:()=>({...X,level:L,js:X.js.slice(),N:kt(),perParticle:Bt,composite:f.composite})}}var po=.15,Re=[{a:{pos:[12,6.6,18],tgt:[0,.4,14],hfov:60,focus:12.5,ap:.6,blur:8,roll:0},b:{pos:[12,5.2,18],tgt:[0,-.3,14]}},{a:{pos:[9,2.1,8],tgt:[5.2,1.1,19],hfov:58,focus:10,ap:.6,blur:8,roll:.06},b:{pos:[9,1,8],tgt:[5.2,.6,19],roll:.04}},{a:{pos:[-4.4,-1.9,7.5],tgt:[-6.6,.4,18.5],hfov:50,focus:11,ap:.6,blur:8,roll:-.08},b:{pos:[-4.4,-3,7.5],tgt:[-6.6,-.1,18.5],roll:-.06}},{form:1,a:{pos:[0,1.6,15],tgt:[0,0,0],hfov:58,focus:15,ap:.8,blur:10,roll:.02},b:{},portrait:{a:{pos:[0,1.4,15.5],tgt:[0,0,0],hfov:46,focus:15.5,ap:.8,blur:10,roll:.02},b:{}},glows:vo,trail:{time:1.1,width:.7,alpha:{dark:.55,light:.5}}}];function vo(t,e){let o=Math.PI/Y.w,n=(Y.twist*t/Y.w%o+o)%o;return[-1,0,1].map(s=>{let a=n+(s-.5)*o,u=1-be(a,e);return{p:[a,0,0],r:.13,a:{dark:.08*u,light:.055*u},ink:4}})}var ke=(t,e,o)=>t.map((n,s)=>D(n,e[s],o));function xo(t,e,o){let n={pos:ke(t.pos,e.pos??t.pos,o),tgt:ke(t.tgt,e.tgt??t.tgt,o)};for(let s of["hfov","roll","focus","ap","blur"])n[s]=D(t[s]??0,e[s]??t[s]??0,o);return n.exp=1,n}function wo({hero:t,frames:e,header:o,reduced:n}){let s=t.closest("main")||document.body,a=v=>t.querySelector(v),u={role:a(".hero__role"),lede:a(".hero__lede"),cta:a(".hero__cta"),cue:a(".cue")},l=t.nextElementSibling,c=null,f=v=>{let w=0,b=0;for(let g=v;g;g=g.offsetParent)w+=g.offsetLeft,b+=g.offsetTop;return{x0:w,y0:b,x1:w+v.offsetWidth,y1:b+v.offsetHeight}};function m(){let v=document.documentElement.clientWidth;c={W:v,desk:v>=960,header:o?o.offsetHeight:64,hero:f(t),first:l?f(l).y0:f(t).y1,windows:e.map(f),copy:Object.fromEntries(Object.entries(u).filter(([,w])=>w).map(([w,b])=>[w,f(b)]))}}let E=()=>window.scrollY,y=v=>tt(0,Math.max(1,c.first-.32*v),E());function d(v,w){let b=c.copy;return c.desk?{colX:Math.max(b.lede?.x1??0,b.cta?.x1??0,b.role?.x1??0)+24,colS:.9,bottomY:(b.cue?.y0??c.hero.y1-80)-20-v,bottomS:.82,topH:c.header+12-v,topS:.85,f:Math.max(140,.12*w)}:{topH:Math.max(c.header+8,(b.role?.y1??0)+16)-v,topS:.9,bottomY:(b.lede?.y0??.6*c.hero.y1)-18-v,bottomS:.93,f:90}}function L(v){c||m();let{W:w,H:b,top:g,vh:V,sy:i}=v,h=[],k=c.desk?0:1;if(c.hero.y1-g>0){let T={y:c.hero.y0+po*i-g,h:V};h.push({id:"hero",rect:{x0:-400,y0:c.hero.y0-400-g,x1:w+400,y1:c.hero.y1-g,f:.24*V},box:T,veil:d(g,w),param:k})}return c.windows.forEach((T,A)=>{let S=T.y0-g,O=T.y1-g,R=O-S;if(R<=0||O<0||S>b)return;let N=Re[A%Re.length],et=!c.desk&&N.portrait?N.portrait:N,C=I(((T.y0+T.y1)/2-i-V/2)/(V/2+R/2),-1,1),j=n.matches?.5:(1-C)/2,ot=xo(et.a,et.b,j),wt=ot.hfov*(c.desk||N.portrait?1:.74);ot.fov=2*Math.atan(Math.tan(wt*Math.PI/360)/(w/b))*180/Math.PI,ot.shift=[0,1-(S+O)/b];let M=N.form===1?ye(j,k):k,nt=typeof N.glows=="function"?N.glows(v.ft,M):N.glows;h.push({id:`w${A+1}`,rect:{x0:-400,y0:S,x1:w+400,y1:O,f:.34*R},pose:ot,form:N.form||0,param:M,glows:nt,trail:N.trail})}),h}let W=(v=0)=>{c||m();let w=E(),b=window.innerHeight;return c.hero.y1-w>-v||c.windows.some(g=>g.y1-w>-v&&g.y0-w<b+v)},U=(v,w)=>D(v==="light"?.3:.55,0,y(w));m();let F=new ResizeObserver(m);return F.observe(s),window.addEventListener("resize",m),{views:L,visible:W,vignette:U,layout:()=>c,update:m,destroy(){F.disconnect(),window.removeEventListener("resize",m)}}}export{K as STILL,wo as createWindows,ho as mount,oo as nameMotion};
