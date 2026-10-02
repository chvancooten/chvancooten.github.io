var It="bool bad(float x){return (floatBitsToUint(x)&0x7f800000u)==0x7f800000u;}",ae=`#version 300 es
precision highp float;
precision highp int;
${It}
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
`,Vt=`
${It}
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
`,zt="gl_Position=vec4(-9.,-9.,0.,1.);",Ve=t=>`${ae}
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
  if(d<.05||al<.0015){${zt}vQ=vec2(0.);vS=vec3(1.);vC=vec4(0.);return;}
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
  if(bad(px.x+px.y+hl+re+blur+al+a.c.x+a.c.y+a.c.z)){${zt}vQ=vec2(0.);vS=vec3(1.);vC=vec4(0.);return;}
  vQ=vec2(cr.x*hl,cr.y*re);
  vS=vec3(L*.5,re,smoothstep(1.6*uDpr,7.*uDpr,blur));
  vC=vec4(a.c*al,al);
  gl_Position=vec4(px/uRes*2.-1.,0.,1.);
}`,Ce=`#version 300 es
precision highp float;
${Vt}
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
}`,st=5,De=t=>`${ae}
${t}
uniform vec3 uTrail;
out float vV;
out vec4 vC;
void main(){
  int i=gl_VertexID>>1;
  float side=float(gl_VertexID&1)*2.-1.;
  uint id=uint(gl_InstanceID);
  vec4 h=hash4(id);
  float u=float(i)/${st}.;
  int j=i<${st}?i+1:i-1;
  float uj=float(j)/${st}.;
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
  if(!(d>=.05)||bad(sa.x+sa.y)){${zt}return;}
  if(!(cb.w>=.05)||!(al>=.001)){gl_Position=vec4(sa/uRes*2.-1.,0.,1.);return;}
  vec2 sb=(cb.xy/cb.w*.5+.5)*uRes;
  vec2 dv=i<${st}?sb-sa:sa-sb;
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
}`,Oe=`#version 300 es
precision highp float;
${Vt}
in float vV;
in vec4 vC;
uniform float uAccS;
out vec4 o;
void main(){
  o=vC*(exp(-vV*vV*2.6)*shade(gl_FragCoord.xy)*uAccS);
  if(bad(o.r+o.g+o.b+o.a))o=vec4(0.);
}`,ie=`#version 300 es
void main(){vec2 p=vec2(float((gl_VertexID<<1)&2),float(gl_VertexID&2));gl_Position=vec4(p*2.-1.,0.,1.);}`,bt=6,Ne=`#version 300 es
precision highp float;
${Vt}
uniform vec2 uRes;
uniform vec3 uBg;
uniform float uLight;
uniform vec4 uG[${bt}];
uniform vec3 uGC[${bt}];
uniform float uVig;
uniform float uPS;
out vec4 o;
void main(){
  vec2 p=gl_FragCoord.xy*uPS;
  vec3 c=uBg,gl=vec3(0.);
  for(int i=0;i<${bt};i++){
    vec2 d=(p-uG[i].xy)/max(uG[i].z,1.);
    gl+=(uLight>.5?uGC[i]-uBg:uGC[i])*uG[i].w*exp(-dot(d,d));
  }
  c+=gl*shade(p);
  vec2 v=p/uRes-.5;
  v.x*=uRes.x/uRes.y;
  float vg=uVig*dot(v,v);
  o=vec4(uLight>.5?c-vec3(.035,.045,.03)*vg:c*(1.-vg),1.);
}`,Be=`#version 300 es
precision highp float;
${It}
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
}`,Ct=4+2*(st+1),St=bt,ft=4;function Dt(t,e){let r=[],o=t.getExtension("KHR_parallel_shader_compile"),a=(i,h)=>{let P=t.createProgram();for(let[A,L]of[[t.VERTEX_SHADER,i],[t.FRAGMENT_SHADER,h]]){let R=t.createShader(A);t.shaderSource(R,L),t.compileShader(R),t.attachShader(P,R),r.push(R)}return t.linkProgram(P),P},n={bg:a(ie,Ne),trail:a(De(e),Oe),head:a(Ve(e),Ce),comp:a(ie,Be)},u=o?null:t.fenceSync(t.SYNC_GPU_COMMANDS_COMPLETE,0);t.flush();let l=t.createVertexArray(),c=!!(t.getExtension("EXT_color_buffer_float")||t.getExtension("EXT_color_buffer_half_float")),f=c?1:.25,m=[],E=[],y=null,v="pending",g=0,G=0;function O(i){let h={},P=t.getProgramParameter(i,t.ACTIVE_UNIFORMS);for(let A=0;A<P;A++){let L=t.getActiveUniform(i,A).name;h[L.replace("[0]","")]=t.getUniformLocation(i,L)}return{p:i,u:h}}function k(){if(v!=="pending")return v;if(o){if(!Object.values(n).every(i=>t.getProgramParameter(i,o.COMPLETION_STATUS_KHR)))return v}else if(u){if(t.getSyncParameter(u,t.SYNC_STATUS)!==t.SIGNALED)return v;t.deleteSync(u),u=null}for(let[i,h]of Object.entries(n))if(!t.getProgramParameter(h,t.LINK_STATUS))return console.warn(`scene: the ${i} program did not link`,t.getProgramInfoLog(h)),v="failed",v;return y=Object.fromEntries(Object.entries(n).map(([i,h])=>[i,O(h)])),v="ready",v}function p(i,h,P,A,L,R){m[i]||(m[i]=t.createTexture(),E[i]=t.createFramebuffer()),t.bindTexture(t.TEXTURE_2D,m[i]),t.texImage2D(t.TEXTURE_2D,0,A,h,P,0,t.RGBA,L,null),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_MIN_FILTER,R),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_MAG_FILTER,R),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_WRAP_S,t.CLAMP_TO_EDGE),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_WRAP_T,t.CLAMP_TO_EDGE),t.bindFramebuffer(t.FRAMEBUFFER,E[i]),t.framebufferTexture2D(t.FRAMEBUFFER,t.COLOR_ATTACHMENT0,t.TEXTURE_2D,m[i],0)}function x(i,h){i===g&&h===G||(g=i,G=h,p(0,Math.ceil(i/ft),Math.ceil(h/ft),t.RGBA8,t.UNSIGNED_BYTE,t.LINEAR),p(1,i,h,c?t.RGBA16F:t.RGBA8,c?t.HALF_FLOAT:t.UNSIGNED_BYTE,t.LINEAR),c&&t.checkFramebufferStatus(t.FRAMEBUFFER)!==t.FRAMEBUFFER_COMPLETE&&(c=!1,f=.25,p(1,i,h,t.RGBA8,t.UNSIGNED_BYTE,t.LINEAR)))}function w(i,h){t.uniform4f(i.u.uMask,h.only,0,h.n,0),t.uniform4fv(i.u.uRects,h.rects),t.uniform1fv(i.u.uRectF,h.feather),t.uniform4fv(i.u.uVeil,h.veil),t.uniform4fv(i.u.uVeil2,h.veil2)}function F(i){x(i.W,i.H),t.bindVertexArray(l),t.disable(t.BLEND),t.bindFramebuffer(t.FRAMEBUFFER,E[0]),t.viewport(0,0,Math.ceil(i.W/ft),Math.ceil(i.H/ft));let h=y.bg;t.useProgram(h.p),t.uniform1f(h.u.uPS,ft),t.uniform2f(h.u.uRes,i.W,i.H),t.uniform3fv(h.u.uBg,i.bg),t.uniform1f(h.u.uLight,i.light),t.uniform4fv(h.u.uG,i.glows),t.uniform3fv(h.u.uGC,i.glowInks),t.uniform1f(h.u.uVig,i.vignette),w(h,i.bgMask),t.drawArrays(t.TRIANGLES,0,3),t.bindFramebuffer(t.FRAMEBUFFER,E[1]),t.viewport(0,0,i.W,i.H),t.clearColor(0,0,0,0),t.clear(t.COLOR_BUFFER_BIT),t.enable(t.BLEND),t.blendFunc(t.ONE,t.ONE),t.blendEquation(t.FUNC_ADD),t.enable(t.SCISSOR_TEST);let P=6;for(let L of i.views){let R=L.mask.box;if(R[2]<=0||R[3]<=0)continue;t.scissor(R[0],R[1],R[2],R[3]);let M=T=>{t.useProgram(T.p),t.uniformMatrix4fv(T.u.uVP,!1,L.VP),T.u.uVPp&&t.uniformMatrix4fv(T.u.uVPp,!1,L.VPp),t.uniform2f(T.u.uRes,i.W,i.H),t.uniform1f(T.u.uFocal,L.focal),t.uniform1f(T.u.uDpr,i.dpr),t.uniform4fv(T.u.uTime,L.time),t.uniform4fv(T.u.uLens,L.lens),t.uniform4fv(T.u.uFog,L.fog),t.uniform1f(T.u.uGain,L.gain),t.uniform3fv(T.u.uInk,i.inks),t.uniform1f(T.u.uN,i.n),t.uniform4fv(T.u.uP,L.params),t.uniform1f(T.u.uAccS,f),w(T,L.mask)};M(y.trail),t.uniform3fv(y.trail.u.uTrail,L.trail),t.drawArraysInstanced(t.TRIANGLE_STRIP,0,2*(st+1),i.n),M(y.head),t.drawArraysInstanced(t.TRIANGLE_STRIP,0,4,i.n),P+=i.n*Ct}t.disable(t.SCISSOR_TEST),t.bindFramebuffer(t.FRAMEBUFFER,null),t.viewport(0,0,i.OW,i.OH),t.disable(t.BLEND);let A=y.comp;return t.useProgram(A.p),t.activeTexture(t.TEXTURE0),t.bindTexture(t.TEXTURE_2D,m[1]),t.uniform1i(A.u.uAcc,0),t.activeTexture(t.TEXTURE1),t.bindTexture(t.TEXTURE_2D,m[0]),t.uniform1i(A.u.uBgT,1),t.activeTexture(t.TEXTURE0),t.uniform2f(A.u.uOut,i.OW,i.OH),t.uniform1f(A.u.uLight,i.light),t.uniform1f(A.u.uSeed,i.seed),t.uniform3f(A.u.uComp,i.comp[0],i.comp[1],1/f),t.drawArrays(t.TRIANGLES,0,3),P}function W(){u&&t.deleteSync(u);for(let i of Object.values(n))t.deleteProgram(i);for(let i of r)t.deleteShader(i);for(let i of m)t.deleteTexture(i);for(let i of E)t.deleteFramebuffer(i);t.deleteVertexArray(l)}return{poll:k,draw:F,dispose:W,get composite(){return c?"rgba16f":"rgba8"}}}var I=(t,e,r)=>Math.min(r,Math.max(e,t)),V=(t,e,r)=>t+(e-t)*r,Y=(t,e,r)=>{let o=I((r-t)/(e-t),0,1);return o*o*(3-2*o)},ue=t=>1-Math.pow(1-I(t,0,1),3),Ge=(t,e)=>[t[0]-e[0],t[1]-e[1],t[2]-e[2]],Et=(t,e)=>t[0]*e[0]+t[1]*e[1]+t[2]*e[2],se=(t,e)=>[t[1]*e[2]-t[2]*e[1],t[2]*e[0]-t[0]*e[2],t[0]*e[1]-t[1]*e[0]],ce=t=>{let e=Math.hypot(t[0],t[1],t[2])||1;return[t[0]/e,t[1]/e,t[2]/e]};function fe(t,e,r=0){let o=ce(Ge(e,t)),a=se(o,[0,1,0]);a=Math.hypot(a[0],a[1],a[2])<1e-4?[1,0,0]:ce(a);let n=se(a,o);if(r){let u=Math.cos(r),l=Math.sin(r),c=[0,1,2].map(f=>a[f]*u+n[f]*l);n=[0,1,2].map(f=>n[f]*u-a[f]*l),a=c}return{r:a,u:n,f:o}}function Nt(t,e,r,o=.05,a=400){let{r:n,u,f:l}=fe(e.pos,e.tgt,e.roll||0),c=e.pos,f=1/Math.tan(e.fov*Math.PI/360),[m,E]=e.shift||[0,0],y=f/r,v=-(a+o)/(a-o),g=-2*a*o/(a-o),G=[l[0],l[1],l[2],-Et(l,c)],O=[[y*n[0],y*n[1],y*n[2],-y*Et(n,c)],[f*u[0],f*u[1],f*u[2],-f*Et(u,c)],[-v*l[0],-v*l[1],-v*l[2],v*Et(l,c)+g],G];for(let k=0;k<4;k++)O[0][k]+=m*G[k],O[1][k]+=E*G[k];for(let k=0;k<4;k++)for(let p=0;p<4;p++)t[k*4+p]=O[p][k];return t}function le(t,e,r,o){let a=t[0]*e[0]+t[4]*e[1]+t[8]*e[2]+t[12],n=t[1]*e[0]+t[5]*e[1]+t[9]*e[2]+t[13],u=t[3]*e[0]+t[7]*e[1]+t[11]*e[2]+t[15];return u<=.01?null:[(a/u*.5+.5)*r,(n/u*.5+.5)*o,u]}function Ue(t,e){let r=t.length,o=[],a=new Array(r).fill(0);for(let n=0;n<r-1;n++)o[n]=(e[n+1]-e[n])/(t[n+1]-t[n]);for(let n=1;n<r-1;n++)a[n]=o[n-1]*o[n]<=0?0:2*o[n-1]*o[n]/(o[n-1]+o[n]);return n=>{if(n<=t[0])return e[0];if(n>=t[r-1])return e[r-1];let u=0;for(;n>t[u+1];)u++;let l=t[u+1]-t[u],c=(n-t[u])/l,f=c*c,m=f*c;return(2*m-3*f+1)*e[u]+(m-2*f+c)*l*a[u]+(-2*m+3*f)*e[u+1]+(m-f)*l*a[u+1]}}var Ot=(t,e,r,o,a)=>.5*(2*e+(-t+r)*a+(2*t-5*e+4*r-o)*a*a+(-t+3*e-3*r+o)*a*a*a),$e=["roll","fov","focus","ap","blur","exp"];function Bt(t){let e=t.length,r=Ue(t.map(o=>o.t),t.map((o,a)=>a));return(o,a)=>{let n=r(o),u=Math.min(e-2,Math.max(0,Math.floor(n))),l=n-u,c=t[Math.max(0,u-1)],f=t[u],m=t[u+1],E=t[Math.min(e-1,u+2)];a.pos=[0,1,2].map(v=>Ot(c.pos[v],f.pos[v],m.pos[v],E.pos[v],l)),a.tgt=[0,1,2].map(v=>Ot(c.tgt[v],f.tgt[v],m.tgt[v],E.tgt[v],l));for(let v of $e)a[v]=Ot(c[v],f[v],m[v],E[v],l);let y=l*l*(3-2*l);return a.shift=[V(f.shift[0],m.shift[0],y),V(f.shift[1],m.shift[1],y)],a}}function me(t,e,r){return t.map((o,a)=>{let n=e[a],u={t:o.t};for(let l of Object.keys(o)){if(l==="t")continue;let c=o[l],f=n[l];u[l]=Array.isArray(c)?c.map((m,E)=>V(m,f[E],r)):V(c,f,r)}return u})}function Gt(t,e,r,o,a=.25){let{r:n,u,f:l}=fe(t.pos,t.tgt,t.roll||0);for(let c=0;c<3;c++){let f=n[c]*e+u[c]*r+l[c]*o;t.pos[c]+=f,t.tgt[c]+=f*a}return t}var j={w:.55,twist:.12,flow:.3,radius:1.25,length:46},Ut={z:-4.3,narrow:-1.5,half:1.4},Q={a:-2,b:3.5,enter:9,leave:-5},pe=(t,e)=>Y(Q.a,Q.b,t-V(Q.enter,Q.leave,e)),$=t=>t.toFixed(4),We=`
const float ZT=44.,ZL=88.;
const float SW=${$(j.w)},ST=${$(j.twist)},SV=${$(j.flow)},SA=${$(j.radius)},SL=${$(j.length)};
const float FZ=${$(Ut.z)},FN=${$(Ut.narrow)},FH=${$(Ut.half)};
const float ZA=${$(Q.a)},ZB=${$(Q.b)},ZE=${$(Q.enter)},ZX=${$(Q.leave)};
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
float zip(float x){return smoothstep(ZA,ZB,x-mix(ZE,ZX,uP.w));}
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
}`,Wt=3,$t=[{t:0,pos:[2.2,1,-26],tgt:[.4,.2,-4],roll:.06,fov:42,focus:18,ap:1.6,blur:18,exp:.95,shift:[.1,0]},{t:.3,pos:[2.3,1,-26.8],tgt:[.4,.2,-4.4],roll:.065,fov:41.6,focus:18,ap:1.6,blur:18,exp:1,shift:[.1,0]},{t:1.3,pos:[3.4,1.6,-13],tgt:[.2,.1,0],roll:.1,fov:42,focus:10,ap:2,blur:18,exp:1,shift:[.15,0]},{t:2.1,pos:[6,4,-9.6],tgt:[0,0,-.2],roll:.03,fov:40,focus:11,ap:3.5,blur:22,exp:1,shift:[.24,.03]},{t:2.6,pos:[7.6,5.15,-11.6],tgt:[0,0,-.5],roll:-.004,fov:39.6,focus:13.5,ap:4.2,blur:26,exp:1,shift:[.26,.03]},{t:3,pos:[7.4,5,-11.3],tgt:[0,0,-.5],roll:0,fov:40,focus:13.5,ap:4.2,blur:26,exp:1,shift:[.26,.03]}],he=[{t:0,pos:[1.4,.8,-27],tgt:[.2,.3,0],roll:.05,fov:56,focus:20,ap:1.6,blur:18,exp:.95,shift:[0,0]},{t:.3,pos:[1.45,.8,-27.8],tgt:[.2,.3,0],roll:.055,fov:55.6,focus:20,ap:1.6,blur:18,exp:1,shift:[0,0]},{t:1.3,pos:[1.8,1.4,-15.5],tgt:[0,.3,2],roll:.08,fov:57,focus:12,ap:2,blur:18,exp:1,shift:[0,0]},{t:2.1,pos:[.9,3,-12.8],tgt:[0,.5,3.6],roll:.02,fov:58,focus:12,ap:3.4,blur:22,exp:1,shift:[0,0]},{t:2.6,pos:[.45,3.6,-12],tgt:[0,.5,4],roll:-.004,fov:58,focus:13,ap:4,blur:24,exp:1,shift:[0,0]},{t:3,pos:[.5,3.5,-12.2],tgt:[0,.5,4],roll:0,fov:58,focus:13,ap:4,blur:24,exp:1,shift:[0,0]}];function qe(t,e,r){let o=Y(Wt,Wt+2.2,e);return o>0&&Gt(t,Math.sin(r*.13)*.32*o,Math.sin(r*.09+1.2)*.16*o,Math.sin(r*.071)*.22*o,.15),t}var Xe=[{p:[0,0,0],r:.2,a:{dark:.18,light:.12},ink:4},{p:[4.5,.5,16],r:.32,a:{dark:.05,light:.035},ink:0},{p:[-4.5,-.5,16],r:.32,a:{dark:.05,light:.035},ink:2}],je=t=>({y:.04*t,s:1+.05*t});function ve(){let t=Bt($t);return{N:26e3,T:Wt,glsl:We,gain:{dark:.95,light:.9},composite:{dark:[2.6,.35],light:[2.4,0]},trail:{time:.3,width:.75,alpha:{dark:.55,light:.5}},vignette:{dark:.55,light:.3},fog:[9,.042,.9,2.6],layout(e){t=Bt(e<=0?$t:e>=1?he:me($t,he,e))},glows(e){let r=Y(.15,1.7,e);return Xe.map(o=>({...o,a:{dark:o.a.dark*r,light:o.a.light*r}}))},pose(e,r,o,a){return t(r,e),Gt(e,a[0]*.6,a[1]*.32,0,.18),qe(e,r,o)}}}var mo=window.matchMedia("(prefers-reduced-motion: reduce)");function lt(t,e,r,o){let a=t.x-e,n=Math.exp(-r*o),u=t.v+r*a;return t.x=e+(a+u*o)*n,t.v=(t.v-r*u*o)*n,Math.abs(t.x-e)+Math.abs(t.v)*.05}var de="scene-quality",He=2560*1600,qt=[1,1,.5,.25,.125,.0625,.03125,.03125],Ze=[1,1,1,.85,.75,.65,.55,.4],H=8,Ke=t=>Math.min(2.8,(1/qt[t])**.3),Ye=t=>Math.min(2.6,(1/qt[t])**.32),xe=2,Qe=45,Je=420,Lt=1/30,we=12,to=["red","red-2","blue","blue-2","purple","dust"],eo=new Set(["Shift","Control","Alt","Meta","CapsLock","Fn","OS"]),ye=t=>{try{return t(sessionStorage)}catch{return null}},mt=t=>{try{performance.mark("scene:"+t)}catch{}};function oo(t){let e=String(t||"").trim(),r=/^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(e);if(r){let o=r[1].length===3?r[1].replace(/./g,"$&$&"):r[1];return[0,2,4].map(a=>parseInt(o.slice(a,a+2),16)/255)}return r=/^rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)/i.exec(e),r?[r[1],r[2],r[3]].map(o=>I(parseFloat(o)/255,0,1)):null}function ro(t){let e=t.getExtension("WEBGL_debug_renderer_info"),r=e?t.getParameter(e.UNMASKED_RENDERER_WEBGL):"";return/swiftshader|llvmpipe|softpipe|software|basic render/i.test(String(r))}var be=()=>({only:0,n:0,rects:new Float32Array(32),feather:new Float32Array(8),veil:new Float32Array(4),veil2:new Float32Array(4),box:new Int32Array(4)});function Se(t,e,r,o,a,n){t.rects.fill(0),t.feather.fill(0),t.only=e?1:0,t.n=e?Math.min(8,e.length):0;let u=e?a:0,l=e?n:0,c=e?0:a,f=e?0:n;for(let E=0;E<t.n;E++){let y=e[E],v=[y.x0*o,n-y.y1*o,y.x1*o,n-y.y0*o];t.rects.set(v,E*4),t.feather[E]=(y.f??120)*o,u=Math.min(u,v[0]),l=Math.min(l,v[1]),c=Math.max(c,v[2]),f=Math.max(f,v[3])}u=I(Math.floor(u),0,a),l=I(Math.floor(l),0,n),t.box.set([u,l,Math.max(0,I(Math.ceil(c),0,a)-u),Math.max(0,I(Math.ceil(f),0,n)-l)]);let m=r||{};t.veil.set([(m.colX??0)*o,m.colS??0,n-(m.bottomY??0)*o,m.bottomS??0]),t.veil2.set([(m.topH??0)*o,m.topS??0,(m.f??160)*o,n])}function no(t,e={}){let r=document.createElement("canvas");r.setAttribute("aria-hidden","true");let o=r.getContext("webgl2",{alpha:!1,antialias:!1,depth:!1,stencil:!1,premultipliedAlpha:!0,preserveDrawingBuffer:!1,powerPreference:"high-performance"});if(!o)return null;let a=ye(s=>s.getItem(de));if(a===null&&ro(o))return o.getExtension("WEBGL_lose_context")?.loseContext(),null;let n=ve(),u=n.T,l=u+2.2,c=e.reduced||window.matchMedia("(prefers-reduced-motion: reduce)"),f=Dt(o,n.glsl),m=!1,E=!1,y=!1,v=!1,g=I(Math.round(+a||0),0,H),G=!1,O=1,k=1,p=1,x=1,w=1,F=1,W=1,i=1,h=0,P=0,A=!1,L=!1,R=we,M=e.intro&&!c.matches?0:l,T=null,ht=!1,rt=M<u,S={x:{x:0,v:0},y:{x:0,v:0},tx:0,ty:0},J={x:1,v:0,t:1},tt={x:1,v:0,t:1},_={W:p,H:x,OW:O,OH:k,dpr:w,light:0,n:0,vignette:.5,seed:0,comp:[1,0],bg:new Float32Array(3),inks:new Float32Array(18),glows:new Float32Array(St*4),glowInks:new Float32Array(St*3),bgMask:be(),views:[]},Xt=[],Te=s=>Xt[s]||(Xt[s]={VP:new Float32Array(16),VPp:new Float32Array(16),focal:1,gain:1,time:new Float32Array(4),lens:new Float32Array(4),fog:new Float32Array(4),trail:new Float32Array(3),params:new Float32Array(4),mask:be()}),Z="dark",Tt=[],q={frames:0,js:[],level:g,vertices:0},jt=[],K=(s,d,b,z)=>{s.addEventListener(d,b,z),jt.push([s,d,b,z])},pt=()=>M<u,gt=()=>Math.max(64,Math.round(n.N*qt[Math.min(g,H-1)]));function Mt(){let s=getComputedStyle(t),d=(z,N)=>oo(s.getPropertyValue(z))||N,b=s.getPropertyValue("--scene-ink").trim()==="ink";Z=b?"light":"dark",_.light=b?1:0,_.bg.set(d("--scene-bg",b?[1,.988,.941]:[.063,.059,.059])),to.forEach((z,N)=>_.inks.set(d(`--scene-${z}`,[.55,.5,.75]),N*3))}function vt(){let s=t.getBoundingClientRect(),d=window.devicePixelRatio||1,b=g>=1?Math.min(1,d):Math.min(2,d);b=Math.min(b,Math.sqrt(He/Math.max(1,s.width*s.height)));let z=Math.max(1,Math.round(s.width*b)),N=Math.max(1,Math.round(s.height*b)),at=Ze[Math.min(g,H-1)],xt=Math.max(1,Math.round(z*at)),wt=Math.max(1,Math.round(N*at));return F=Math.max(1,s.width),W=Math.max(1,s.height),i=F/W,xt===p&&wt===x&&z===O&&N===k?!1:(O=z,k=N,p=xt,x=wt,w=p/F,r.width=O,r.height=k,n.layout(1-Y(.62,1.25,i)),!0)}function ge(){let s=M,d=R,b=[S.x.x,S.y.x],z={it:s,ft:d,T:u,W:F,H:W,theme:Z},N=e.views?e.views(z):[{id:"hero"}],at=1-J.x,xt=I(tt.x,0,1),wt=gt();_.W=p,_.H=x,_.OW=O,_.OH=k,_.dpr=w,_.n=wt,_.vignette=e.vignette?e.vignette(Z,W):n.vignette[Z],_.comp=n.composite[Z],_.seed=d*60%97,_.glows.fill(0),_.views.length=0;let yt=0;Tt=[],N.forEach((U,Ie)=>{let C=Te(Ie),B=U.pose,ut=U.pose;B||(B=n.pose({},s,d,b),ut=n.pose({},s-Lt,d-Lt,b));for(let D of B===ut?[B]:[B,ut])D.focus=V(D.focus,1.6,at),D.ap=V(D.ap,7,at),D.blur=V(D.blur,15,at);Nt(C.VP,B,i),ut===B?C.VPp.set(C.VP):Nt(C.VPp,ut,i);let ne=(B.exp??1)*xt,Ft=U.trail||n.trail;C.focal=.5*x/Math.tan(B.fov*Math.PI/360),C.gain=n.gain[Z]*ne*Ye(Math.min(g,H-1)),C.time.set([d,s,d-Lt,s-Lt]),C.lens.set([B.focus,B.ap*w,B.blur*w,w*Ke(Math.min(g,H-1))]),C.fog.set(n.fog),C.trail.set([Ft.time,Ft.width,Ft.alpha[Z]]),C.params.set([0,0,U.form||0,U.param||0]),Se(C.mask,U.rect?[U.rect]:null,U.veil,w,p,x),_.views.push(C);for(let D of U.glows||n.glows(s)){let Pt=yt<St&&le(C.VP,D.p,p,x);Pt&&(_.glows.set([Pt[0],Pt[1],D.r*x,D.a[Z]*ne],yt*4),_.glowInks.set(_.inks.subarray(D.ink*3,D.ink*3+3),yt*3),yt++)}Tt.push({id:U.id??null,pos:B.pos.map(D=>Math.round(D*1e3)/1e3)})});let ze=N.map(U=>U.rect).filter(Boolean);return Se(_.bgMask,e.views?ze:null,N[0]?.veil,w,p,x),{it:s,T:u}}function nt(){if(!m||y)return 0;let s=performance.now(),d=ge();q.vertices=f.draw(_),v||(v=!0,t.append(r),mt(pt()?"first-frame:intro":"first-frame"),requestAnimationFrame(()=>{!y&&!E&&t.classList.add("is-shown")})),e.onFrame?.(d);let b=performance.now()-s;return q.frames++,q.js.push(b),q.js.length>600&&q.js.shift(),b}function Ht(s){rt&&(rt=!1,mt("intro-end:"+s),e.onIntroEnd?.(s))}function Me(){pt()&&Ht("stopped"),M=Math.max(M,l),T=null;for(let s of[J,tt])s.x=s.t,s.v=0;c.matches&&(S.tx=S.ty=0),S.x.x=S.tx,S.y.x=S.ty,S.x.v=S.y.v=0}function et(){!m||y||(Me(),nt())}let ot=()=>m&&!y&&!A&&!G&&!c.matches&&g<H,Ae=()=>e.visible?e.visible():!0,Zt=()=>ot()&&!document.hidden&&Ae(),ct=[],Kt=0;function Re(s){if(g>=H-1||Kt++<xe||s>1e3||(ct.push(s),ct.length<(Kt<=xe+8?4:20)))return;let d=ct.slice().sort((z,N)=>z-N)[ct.length>>1];if(ct.length=0,d<=Qe)return;let b=g===0&&(window.devicePixelRatio||1)<=1?1:g;g=Math.min(H-1,Math.max(g+1,b+Math.max(1,Math.ceil(Math.log2(d/28))))),q.level=g,ye(z=>z.setItem(de,String(g))),mt(`quality:${g}:${Math.round(d)}ms`),vt(),e.onQuality?.(g)}function ke(s){if(!(M>=l)){if(T){let d=ue((performance.now()-T.at)/Je);M=V(T.from,u,d),d>=1&&(T=null)}else M=Math.min(l,M+s);M>=u&&Ht(ht?"skipped":"played")}}function Yt(s){if(h=0,!Zt()){P=0,ot()&&!document.hidden&&!L&&(L=!0,nt());return}L=!1;let d=P?s-P:0,b=P?Math.min(.25,d/1e3):1/60;P=s,ke(b),R+=Math.min(.05,b),lt(J,J.t,6,b),lt(tt,tt.t,6,b),lt(S.x,S.tx,3.2,b),lt(S.y,S.ty,3.2,b),nt(),d&&Re(d),Zt()&&(h=requestAnimationFrame(Yt))}let X=()=>{!h&&m&&ot()&&!document.hidden&&(h=requestAnimationFrame(Yt))},it=()=>{h&&cancelAnimationFrame(h),h=0,P=0},At=()=>ot()?X():et(),dt=0,_e=()=>{dt||(dt=requestAnimationFrame(()=>{dt=0,et()}))},Qt=()=>{pt()&&!T&&(T={from:M,at:performance.now()},ht=!0,mt("intro-skip"))},Rt=0;function kt(){if(Rt=0,y)return;let s=f.poll();if(s==="pending"){Rt=requestAnimationFrame(kt);return}if(s==="failed"){Jt("shaders");return}m=!0,mt("ready"),Mt(),vt(),t.classList.add("is-live"),e.onQuality?.(g),ot()?(nt(),X()):et(),e.onReady?.()}function Jt(s){E=!0,m=!1,it(),t.classList.remove("is-live","is-shown"),e.onFail?.(s)}Mt(),kt();let Fe=s=>{(s.type!=="keydown"||!eo.has(s.key))&&Qt()},Pe=requestAnimationFrame(()=>{if(!y)for(let s of["keydown","pointerdown","wheel","touchstart"])K(window,s,Fe,{passive:!0})}),te=(s,d)=>{c.matches||(S.tx=I(s/window.innerWidth*2-1,-1,1),S.ty=I(-(d/window.innerHeight*2-1),-1,1),X())},ee=()=>{S.tx=0,S.ty=0,X()};K(window,"pointermove",s=>{s.pointerType!=="touch"&&te(s.clientX,s.clientY)},{passive:!0}),K(window,"touchmove",s=>{let d=s.touches[0];d&&te(d.clientX,d.clientY)},{passive:!0}),K(window,"touchend",ee,{passive:!0}),K(document,"pointerleave",ee),K(document,"visibilitychange",()=>document.hidden?it():X());let oe=()=>c.matches?(it(),et()):X();c.addEventListener("change",oe);let _t=0,re=new ResizeObserver(()=>{clearTimeout(_t),_t=setTimeout(()=>{!m||!vt()||(ot()?h||(nt(),X()):et())},60)});return re.observe(t),K(r,"webglcontextlost",s=>{s.preventDefault(),Jt("context lost")}),K(r,"webglcontextrestored",()=>{y||(f=Dt(o,n.glsl),E=!1,kt())}),{setScroll(s){(+s||0)*window.innerHeight>8&&Qt(),ot()?X():m&&_e()},setFocus(s){J.t=I(+s,0,1),At()},setIntensity(s){tt.t=I(+s,0,1),At()},pause(){G=!0,it(),et()},resume(){G=!1,At()},restyle(){Mt(),h||et()},destroy(){y=!0,it(),cancelAnimationFrame(Rt),cancelAnimationFrame(Pe),cancelAnimationFrame(dt),clearTimeout(_t);for(let[s,d,b,z]of jt)s.removeEventListener(d,b,z);c.removeEventListener("change",oe),re.disconnect(),f.dispose(),o.getExtension("WEBGL_lose_context")?.loseContext(),r.remove(),t.classList.remove("is-live","is-shown")},get failed(){return E},get level(){return g},seek(s,d={}){if(!m)return!1;it(),A=!0,M=Math.min(Math.max(0,s),l),R=we+s,T=null;let b=d.ptr||[0,0];return S.x.x=S.tx=b[0],S.y.x=S.ty=b[1],S.x.v=S.y.v=0,vt(),nt(),!0},live(){A=!1,X()},clock:()=>({introT:M,flowT:R,introRunning:pt(),level:g,density:gt()/n.N,frames:q.frames,views:Tt}),stats:()=>({...q,level:g,js:q.js.slice(),N:gt(),perParticle:Ct,composite:f.composite})}}var Ee=[{a:{pos:[12,6.6,18],tgt:[0,.4,14],hfov:60,focus:12.5,ap:.6,blur:8,roll:0},b:{pos:[12,5.2,18],tgt:[0,-.3,14]}},{a:{pos:[9,2.1,8],tgt:[5.2,1.1,19],hfov:58,focus:10,ap:.6,blur:8,roll:.06},b:{pos:[9,1,8],tgt:[5.2,.6,19],roll:.04}},{a:{pos:[-4.4,-1.9,7.5],tgt:[-6.6,.4,18.5],hfov:50,focus:11,ap:.6,blur:8,roll:-.08},b:{pos:[-4.4,-3,7.5],tgt:[-6.6,-.1,18.5],roll:-.06}},{form:1,a:{pos:[0,1.6,15],tgt:[0,0,0],hfov:58,focus:15,ap:.8,blur:10,roll:.02},b:{},portrait:{a:{pos:[0,1.4,15.5],tgt:[0,0,0],hfov:46,focus:15.5,ap:.8,blur:10,roll:.02},b:{}},glows:io,trail:{time:1.1,width:.7,alpha:{dark:.55,light:.5}}}];function io(t,e){let r=Math.PI/j.w,o=(j.twist*t/j.w%r+r)%r;return[-1,0,1].map(a=>{let n=o+(a-.5)*r,u=1-pe(n,e);return{p:[n,0,0],r:.13,a:{dark:.08*u,light:.055*u},ink:4}})}var Le=(t,e,r)=>t.map((o,a)=>V(o,e[a],r));function ao(t,e,r){let o={pos:Le(t.pos,e.pos??t.pos,r),tgt:Le(t.tgt,e.tgt??t.tgt,r)};for(let a of["hfov","roll","focus","ap","blur"])o[a]=V(t[a]??0,e[a]??t[a]??0,r);return o.exp=1,o}function so({hero:t,frames:e,header:r,reduced:o}){let a=t.closest("main")||document.body,n=p=>t.querySelector(p),u={role:n(".hero__role"),lede:n(".hero__lede"),cta:n(".hero__cta"),cue:n(".cue")},l=t.nextElementSibling,c=null,f=p=>{let x=0,w=0;for(let F=p;F;F=F.offsetParent)x+=F.offsetLeft,w+=F.offsetTop;return{x0:x,y0:w,x1:x+p.offsetWidth,y1:w+p.offsetHeight}};function m(){let p=document.documentElement.clientWidth;c={W:p,desk:p>=960,header:r?r.offsetHeight:64,hero:f(t),first:l?f(l).y0:f(t).y1,windows:e.map(f),copy:Object.fromEntries(Object.entries(u).filter(([,x])=>x).map(([x,w])=>[x,f(w)]))}}let E=()=>window.scrollY,y=p=>Y(0,Math.max(1,c.first-.32*p),E());function v(p,x){let w=c.copy;return c.desk?{colX:Math.max(w.lede?.x1??0,w.cta?.x1??0,w.role?.x1??0)+24,colS:.9,bottomY:(w.cue?.y0??c.hero.y1-80)-20-p,bottomS:.82,topH:c.header+12,topS:.85,f:Math.max(140,.12*x)}:{topH:Math.max(c.header+8,(w.role?.y1??0)+16-p),topS:.9,bottomY:(w.lede?.y0??.6*c.hero.y1)-18-p,bottomS:.93,f:90}}function g(p){c||m();let x=E(),{W:w,H:F}=p,W=[],i=c.desk?0:1;return c.hero.y1-x>0&&W.push({id:"hero",rect:{x0:-400,y0:c.hero.y0-400-x,x1:w+400,y1:c.hero.y1-x,f:.24*F},veil:v(x,w),param:i}),c.windows.forEach((h,P)=>{let A=h.y0-x,L=h.y1-x,R=L-A;if(R<=0||L<0||A>F)return;let M=Ee[P%Ee.length],T=!c.desk&&M.portrait?M.portrait:M,ht=I(((A+L)/2-F/2)/(F/2+R/2),-1,1),rt=o.matches?.5:(1-ht)/2,S=ao(T.a,T.b,rt),J=S.hfov*(c.desk||M.portrait?1:.74);S.fov=2*Math.atan(Math.tan(J*Math.PI/360)/(w/F))*180/Math.PI,S.shift=[0,1-(A+L)/F];let tt=typeof M.glows=="function"?M.glows(p.ft,rt):M.glows,_=M.form===1?rt:i;W.push({id:`w${P+1}`,rect:{x0:-400,y0:A,x1:w+400,y1:L,f:.34*R},pose:S,form:M.form||0,param:_,glows:tt,trail:M.trail})}),W}let G=()=>{c||m();let p=E(),x=window.innerHeight;return c.hero.y1-p>0||c.windows.some(w=>w.y1-p>0&&w.y0-p<x)},O=(p,x)=>V(p==="light"?.3:.55,0,y(x));m();let k=new ResizeObserver(m);return k.observe(a),window.addEventListener("resize",m),{views:g,visible:G,vignette:O,layout:()=>c,update:m,destroy(){k.disconnect(),window.removeEventListener("resize",m)}}}export{H as STILL,so as createWindows,no as mount,je as nameMotion};
