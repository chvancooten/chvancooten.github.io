var oe=`#version 300 es
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
`,Ft=`
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
`,re="gl_Position=vec4(-9.,-9.,0.,1.);",Pe=t=>`${oe}
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
  if(d<.05||al<.0015){${re}vQ=vec2(0.);vS=vec3(1.);vC=vec4(0.);return;}
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
}`,Fe=`#version 300 es
precision highp float;
${Ft}
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
}`,rt=5,Ie=t=>`${oe}
${t}
uniform vec3 uTrail;
out float vV;
out vec4 vC;
void main(){
  int i=gl_VertexID>>1;
  float side=float(gl_VertexID&1)*2.-1.;
  uint id=uint(gl_InstanceID);
  vec4 h=hash4(id);
  float u=float(i)/${rt}.;
  int j=i<${rt}?i+1:i-1;
  float uj=float(j)/${rt}.;
  Pt a=particle(id,h,uTime.x-uTrail.x*u,uTime.y-uTrail.x*u);
  Pt b=particle(id,h,uTime.x-uTrail.x*uj,uTime.y-uTrail.x*uj);
  vec4 ca=uVP*vec4(a.p,1.);
  vec4 cb=uVP*vec4(b.p,1.);
  float d=ca.w;
  float al=a.a*uGain*uTrail.z*fogAt(d);
  if(d<.05||cb.w<.05||al<.001){${re}vV=0.;vC=vec4(0.);return;}
  vec2 sa=(ca.xy/ca.w*.5+.5)*uRes;
  vec2 sb=(cb.xy/cb.w*.5+.5)*uRes;
  vec2 dv=i<${rt}?sb-sa:sa-sb;
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
}`,ze=`#version 300 es
precision highp float;
${Ft}
in float vV;
in vec4 vC;
uniform float uAccS;
out vec4 o;
void main(){o=vC*(exp(-vV*vV*2.6)*shade(gl_FragCoord.xy)*uAccS);}`,ee=`#version 300 es
void main(){vec2 p=vec2(float((gl_VertexID<<1)&2),float(gl_VertexID&2));gl_Position=vec4(p*2.-1.,0.,1.);}`,yt=6,Ve=`#version 300 es
precision highp float;
${Ft}
uniform vec2 uRes;
uniform vec3 uBg;
uniform float uLight;
uniform vec4 uG[${yt}];
uniform vec3 uGC[${yt}];
uniform float uVig;
uniform float uPS;
out vec4 o;
void main(){
  vec2 p=gl_FragCoord.xy*uPS;
  vec3 c=uBg,gl=vec3(0.);
  for(int i=0;i<${yt};i++){
    vec2 d=(p-uG[i].xy)/max(uG[i].z,1.);
    gl+=(uLight>.5?uGC[i]-uBg:uGC[i])*uG[i].w*exp(-dot(d,d));
  }
  c+=gl*shade(p);
  vec2 v=p/uRes-.5;
  v.x*=uRes.x/uRes.y;
  float vg=uVig*dot(v,v);
  o=vec4(uLight>.5?c-vec3(.035,.045,.03)*vg:c*(1.-vg),1.);
}`,De=`#version 300 es
precision highp float;
uniform sampler2D uAcc;
uniform sampler2D uBgT;
uniform vec2 uRes;
uniform vec2 uOut;
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
  vec2 p=gl_FragCoord.xy,u=p/uOut;
  vec3 bg=texture(uBgT,u).rgb+(fract(sin(dot(p+uSeed,vec2(12.9898,78.233)))*43758.5453)-.5)/170.;
  vec4 s=texture(uAcc,u)*uComp.z;
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
}`,It=4+2*(rt+1),bt=yt,ct=4;function zt(t,e){let r=[],o=t.getExtension("KHR_parallel_shader_compile"),a=(n,l)=>{let R=t.createProgram();for(let[E,g]of[[t.VERTEX_SHADER,n],[t.FRAGMENT_SHADER,l]]){let M=t.createShader(E);t.shaderSource(M,g),t.compileShader(M),t.attachShader(R,M),r.push(M)}return t.linkProgram(R),R},i={bg:a(ee,Ve),trail:a(Ie(e),ze),head:a(Pe(e),Fe),comp:a(ee,De)},u=o?null:t.fenceSync(t.SYNC_GPU_COMMANDS_COMPLETE,0);t.flush();let f=t.createVertexArray(),c=!!t.getExtension("EXT_color_buffer_float"),m=c?1:.25,h=[],A=[],T=null,d="pending",L=0,N=0;function V(n){let l={},R=t.getProgramParameter(n,t.ACTIVE_UNIFORMS);for(let E=0;E<R;E++){let g=t.getActiveUniform(n,E).name;l[g.replace("[0]","")]=t.getUniformLocation(n,g)}return{p:n,u:l}}function k(){if(d!=="pending")return d;if(o){if(!Object.values(i).every(n=>t.getProgramParameter(n,o.COMPLETION_STATUS_KHR)))return d}else if(u){if(t.getSyncParameter(u,t.SYNC_STATUS)!==t.SIGNALED)return d;t.deleteSync(u),u=null}for(let[n,l]of Object.entries(i))if(!t.getProgramParameter(l,t.LINK_STATUS))return console.warn(`scene: the ${n} program did not link`,t.getProgramInfoLog(l)),d="failed",d;return T=Object.fromEntries(Object.entries(i).map(([n,l])=>[n,V(l)])),d="ready",d}function p(n,l,R,E,g,M){h[n]||(h[n]=t.createTexture(),A[n]=t.createFramebuffer()),t.bindTexture(t.TEXTURE_2D,h[n]),t.texImage2D(t.TEXTURE_2D,0,E,l,R,0,t.RGBA,g,null),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_MIN_FILTER,M),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_MAG_FILTER,M),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_WRAP_S,t.CLAMP_TO_EDGE),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_WRAP_T,t.CLAMP_TO_EDGE),t.bindFramebuffer(t.FRAMEBUFFER,A[n]),t.framebufferTexture2D(t.FRAMEBUFFER,t.COLOR_ATTACHMENT0,t.TEXTURE_2D,h[n],0)}function w(n,l){n===L&&l===N||(L=n,N=l,p(0,Math.ceil(n/ct),Math.ceil(l/ct),t.RGBA8,t.UNSIGNED_BYTE,t.LINEAR),p(1,n,l,c?t.RGBA16F:t.RGBA8,c?t.HALF_FLOAT:t.UNSIGNED_BYTE,t.LINEAR))}function y(n,l){t.uniform4f(n.u.uMask,l.only,0,l.n,0),t.uniform4fv(n.u.uRects,l.rects),t.uniform1fv(n.u.uRectF,l.feather),t.uniform4fv(n.u.uVeil,l.veil),t.uniform4fv(n.u.uVeil2,l.veil2)}function _(n){w(n.W,n.H),t.bindVertexArray(f),t.disable(t.BLEND),t.bindFramebuffer(t.FRAMEBUFFER,A[0]),t.viewport(0,0,Math.ceil(n.W/ct),Math.ceil(n.H/ct));let l=T.bg;t.useProgram(l.p),t.uniform1f(l.u.uPS,ct),t.uniform2f(l.u.uRes,n.W,n.H),t.uniform3fv(l.u.uBg,n.bg),t.uniform1f(l.u.uLight,n.light),t.uniform4fv(l.u.uG,n.glows),t.uniform3fv(l.u.uGC,n.glowInks),t.uniform1f(l.u.uVig,n.vignette),y(l,n.bgMask),t.drawArrays(t.TRIANGLES,0,3),t.bindFramebuffer(t.FRAMEBUFFER,A[1]),t.viewport(0,0,n.W,n.H),t.clearColor(0,0,0,0),t.clear(t.COLOR_BUFFER_BIT),t.enable(t.BLEND),t.blendFunc(t.ONE,t.ONE),t.blendEquation(t.FUNC_ADD);let R=6;for(let g of n.views){let M=x=>{t.useProgram(x.p),t.uniformMatrix4fv(x.u.uVP,!1,g.VP),x.u.uVPp&&t.uniformMatrix4fv(x.u.uVPp,!1,g.VPp),t.uniform2f(x.u.uRes,n.W,n.H),t.uniform1f(x.u.uFocal,g.focal),t.uniform1f(x.u.uDpr,n.dpr),t.uniform4fv(x.u.uTime,g.time),t.uniform4fv(x.u.uLens,g.lens),t.uniform4fv(x.u.uFog,g.fog),t.uniform1f(x.u.uGain,g.gain),t.uniform3fv(x.u.uInk,n.inks),t.uniform1f(x.u.uN,n.n),t.uniform4fv(x.u.uP,g.params),t.uniform1f(x.u.uAccS,m),y(x,g.mask)};M(T.trail),t.uniform3fv(T.trail.u.uTrail,g.trail),t.drawArraysInstanced(t.TRIANGLE_STRIP,0,2*(rt+1),n.n),M(T.head),t.drawArraysInstanced(t.TRIANGLE_STRIP,0,4,n.n),R+=n.n*It}t.bindFramebuffer(t.FRAMEBUFFER,null),t.viewport(0,0,n.OW,n.OH),t.disable(t.BLEND);let E=T.comp;return t.useProgram(E.p),t.activeTexture(t.TEXTURE0),t.bindTexture(t.TEXTURE_2D,h[1]),t.uniform1i(E.u.uAcc,0),t.activeTexture(t.TEXTURE1),t.bindTexture(t.TEXTURE_2D,h[0]),t.uniform1i(E.u.uBgT,1),t.activeTexture(t.TEXTURE0),t.uniform2f(E.u.uOut,n.OW,n.OH),t.uniform1f(E.u.uLight,n.light),t.uniform1f(E.u.uSeed,n.seed),t.uniform3f(E.u.uComp,n.comp[0],n.comp[1],1/m),t.drawArrays(t.TRIANGLES,0,3),R}function U(){u&&t.deleteSync(u);for(let n of Object.values(i))t.deleteProgram(n);for(let n of r)t.deleteShader(n);for(let n of h)t.deleteTexture(n);for(let n of A)t.deleteFramebuffer(n);t.deleteVertexArray(f)}return{poll:k,draw:_,dispose:U,composite:c?"rgba16f":"rgba8"}}var G=(t,e,r)=>Math.min(r,Math.max(e,t)),O=(t,e,r)=>t+(e-t)*r,J=(t,e,r)=>{let o=G((r-t)/(e-t),0,1);return o*o*(3-2*o)},se=t=>1-Math.pow(1-G(t,0,1),3),Ce=(t,e)=>[t[0]-e[0],t[1]-e[1],t[2]-e[2]],Lt=(t,e)=>t[0]*e[0]+t[1]*e[1]+t[2]*e[2],ne=(t,e)=>[t[1]*e[2]-t[2]*e[1],t[2]*e[0]-t[0]*e[2],t[0]*e[1]-t[1]*e[0]],ie=t=>{let e=Math.hypot(t[0],t[1],t[2])||1;return[t[0]/e,t[1]/e,t[2]/e]};function ae(t,e,r=0){let o=ie(Ce(e,t)),a=ne(o,[0,1,0]);a=Math.hypot(a[0],a[1],a[2])<1e-4?[1,0,0]:ie(a);let i=ne(a,o);if(r){let u=Math.cos(r),f=Math.sin(r),c=[0,1,2].map(m=>a[m]*u+i[m]*f);i=[0,1,2].map(m=>i[m]*u-a[m]*f),a=c}return{r:a,u:i,f:o}}function Dt(t,e,r,o=.05,a=400){let{r:i,u,f}=ae(e.pos,e.tgt,e.roll||0),c=e.pos,m=1/Math.tan(e.fov*Math.PI/360),[h,A]=e.shift||[0,0],T=m/r,d=-(a+o)/(a-o),L=-2*a*o/(a-o),N=[f[0],f[1],f[2],-Lt(f,c)],V=[[T*i[0],T*i[1],T*i[2],-T*Lt(i,c)],[m*u[0],m*u[1],m*u[2],-m*Lt(u,c)],[-d*f[0],-d*f[1],-d*f[2],d*Lt(f,c)+L],N];for(let k=0;k<4;k++)V[0][k]+=h*N[k],V[1][k]+=A*N[k];for(let k=0;k<4;k++)for(let p=0;p<4;p++)t[k*4+p]=V[p][k];return t}function ce(t,e,r,o){let a=t[0]*e[0]+t[4]*e[1]+t[8]*e[2]+t[12],i=t[1]*e[0]+t[5]*e[1]+t[9]*e[2]+t[13],u=t[3]*e[0]+t[7]*e[1]+t[11]*e[2]+t[15];return u<=.01?null:[(a/u*.5+.5)*r,(i/u*.5+.5)*o,u]}function Oe(t,e){let r=t.length,o=[],a=new Array(r).fill(0);for(let i=0;i<r-1;i++)o[i]=(e[i+1]-e[i])/(t[i+1]-t[i]);for(let i=1;i<r-1;i++)a[i]=o[i-1]*o[i]<=0?0:2*o[i-1]*o[i]/(o[i-1]+o[i]);return i=>{if(i<=t[0])return e[0];if(i>=t[r-1])return e[r-1];let u=0;for(;i>t[u+1];)u++;let f=t[u+1]-t[u],c=(i-t[u])/f,m=c*c,h=m*c;return(2*h-3*m+1)*e[u]+(h-2*m+c)*f*a[u]+(-2*h+3*m)*e[u+1]+(h-m)*f*a[u+1]}}var Vt=(t,e,r,o,a)=>.5*(2*e+(-t+r)*a+(2*t-5*e+4*r-o)*a*a+(-t+3*e-3*r+o)*a*a*a),Ne=["roll","fov","focus","ap","blur","exp"];function Ct(t){let e=t.length,r=Oe(t.map(o=>o.t),t.map((o,a)=>a));return(o,a)=>{let i=r(o),u=Math.min(e-2,Math.max(0,Math.floor(i))),f=i-u,c=t[Math.max(0,u-1)],m=t[u],h=t[u+1],A=t[Math.min(e-1,u+2)];a.pos=[0,1,2].map(d=>Vt(c.pos[d],m.pos[d],h.pos[d],A.pos[d],f)),a.tgt=[0,1,2].map(d=>Vt(c.tgt[d],m.tgt[d],h.tgt[d],A.tgt[d],f));for(let d of Ne)a[d]=Vt(c[d],m[d],h[d],A[d],f);let T=f*f*(3-2*f);return a.shift=[O(m.shift[0],h.shift[0],T),O(m.shift[1],h.shift[1],T)],a}}function ue(t,e,r){return t.map((o,a)=>{let i=e[a],u={t:o.t};for(let f of Object.keys(o)){if(f==="t")continue;let c=o[f],m=i[f];u[f]=Array.isArray(c)?c.map((h,A)=>O(h,m[A],r)):O(c,m,r)}return u})}function Ot(t,e,r,o,a=.25){let{r:i,u,f}=ae(t.pos,t.tgt,t.roll||0);for(let c=0;c<3;c++){let m=i[c]*e+u[c]*r+f[c]*o;t.pos[c]+=m,t.tgt[c]+=m*a}return t}var q={w:.55,twist:.12,flow:.3,radius:1.25,length:46},ut=t=>t.toFixed(4),Ge=`
const float ZT=44.,ZL=88.;
const float SW=${ut(q.w)},ST=${ut(q.twist)},SV=${ut(q.flow)},SA=${ut(q.radius)},SL=${ut(q.length)};
float twist(float z){return z<0.?1.2*z:1.6*(1.-exp(-z/3.));}
vec3 ctr(float z,float k,out float w,out float S){
  S=pow(smoothstep(-1.,26.,z),.6);
  float R=mix(.2,6.4,S);
  float th=twist(z)-1.28+k*3.14159265;
  vec2 c=vec2(cos(th),sin(th)*mix(1.,.38,S))*R;
  c+=vec2(1.4*sin(.09*z+.3),.8*sin(.06*z+1.4))*S*S;
  w=mix(.11,1.85,S);
  return vec3(c,z);
}
Pt braid(uint id,vec4 h,float t){
  Pt o;
  float f=float(id)/uN;
  if(f<.8){
    float k=float(id&1u);
    float z=ZT-mod(h.x*ZL+(1.2+1.1*h.y)*t,ZL);
    float w,S;
    vec3 c=ctr(z,k,w,S);
    float halo=step(.78,fract(h.z*7.31));
    float rr=w*sqrt(-log(1.-.96*h.z))*.5*(1.+1.5*halo);
    float ph=6.2832*h.w+1.7*z*(1.-.65*S);
    o.p=c+vec3(cos(ph),sin(ph),0.)*rr;
    vec3 base=k<.5?mix(uInk[0],uInk[1],h.y*h.y*.8):mix(uInk[2],uInk[3],h.y*.9);
    o.c=mix(base,uInk[4],smoothstep(5.,-2.5,z)*(h.y<.22?.4:.92));
    float core=exp(-rr*rr/(w*w)*1.6);
    o.a=(.28+.72*core)*(1.-.55*halo)*(1.+.9*exp(-z*z/5.))*mix(.42,1.,S)*smoothstep(-44.,-34.,z)*smoothstep(44.,32.,z);
    o.s=.019*(.7+.6*h.z);
  }else if(f<.875){
    float r=2.9*sqrt(-log(1.-.985*h.x))*.62;
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
    o.a=.2*smoothstep(-44.,-36.,z)*smoothstep(44.,36.,z);
    o.s=.017;
  }
  return o;
}
Pt strands(uint id,vec4 h,float t){
  Pt o;
  float f=float(id)/uN;
  float k=float(id&1u);
  if(f<.86){
    float x=(fract(h.x+t*SV*(.8+.4*h.y)/SL)-.5)*SL;
    float ph=SW*x-ST*t+k*3.14159265;
    float rr=.6*sqrt(-log(1.-.97*h.z));
    float a=6.2832*h.w+1.3*x-.2*t;
    o.p=vec3(x,SA*sin(ph),.9*SA*cos(ph))+vec3(0.,cos(a),sin(a))*rr;
    vec3 base=k<.5?mix(uInk[0],uInk[1],h.y*.6):mix(uInk[2],uInk[3],h.y*.7);
    float s=sin(ph);
    o.c=mix(base,uInk[4],.88*exp(-s*s/.2));
    o.a=.5*(.3+.7*exp(-rr*rr*2.4))*smoothstep(SL*.5,SL*.5-5.,abs(x));
    o.s=.019*(.7+.6*h.z);
  }else if(f<.93){
    float S=3.14159265/SW;
    float x=mod(floor(h.x*8.)*S+ST*t/SW+SL*.5,8.*S)-SL*.5;
    vec3 r=vec3(h.y,h.z,fract(h.w*7.3))-.5;
    o.p=vec3(x,0.,0.)+normalize(r+1e-3)*.75*sqrt(-log(1.-.95*fract(h.w*3.7)));
    o.c=mix(uInk[4],k<.5?uInk[0]:uInk[2],.15*h.y);
    o.a=.36*exp(-dot(o.p.yz,o.p.yz)*.6)*smoothstep(SL*.5,SL*.5-5.,abs(x));
    o.s=.018;
  }else{
    float x=(fract(h.x+t*SV*.5/SL)-.5)*SL;
    o.p=vec3(x,(h.y-.5)*7.,(h.z-.5)*7.);
    o.c=mix(uInk[5],uInk[4],h.w*h.w);
    o.a=.13*smoothstep(SL*.5,SL*.5-5.,abs(x));
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
}`,Gt=3,Nt=[{t:0,pos:[2.2,1,-26],tgt:[.4,.2,-4],roll:.06,fov:42,focus:18,ap:1.6,blur:18,exp:.95,shift:[.1,0]},{t:.3,pos:[2.3,1,-26.8],tgt:[.4,.2,-4.4],roll:.065,fov:41.6,focus:18,ap:1.6,blur:18,exp:1,shift:[.1,0]},{t:1.3,pos:[3.4,1.6,-13],tgt:[.2,.1,0],roll:.1,fov:42,focus:10,ap:2,blur:18,exp:1,shift:[.15,0]},{t:2.1,pos:[6,4,-9.6],tgt:[0,0,-.2],roll:.03,fov:40,focus:11,ap:3.5,blur:22,exp:1,shift:[.24,.03]},{t:2.6,pos:[7.6,5.15,-11.6],tgt:[0,0,-.5],roll:-.004,fov:39.6,focus:13.5,ap:4.2,blur:26,exp:1,shift:[.26,.03]},{t:3,pos:[7.4,5,-11.3],tgt:[0,0,-.5],roll:0,fov:40,focus:13.5,ap:4.2,blur:26,exp:1,shift:[.26,.03]}],fe=[{t:0,pos:[1.4,.8,-27],tgt:[.2,.3,0],roll:.05,fov:56,focus:20,ap:1.6,blur:18,exp:.95,shift:[0,0]},{t:.3,pos:[1.45,.8,-27.8],tgt:[.2,.3,0],roll:.055,fov:55.6,focus:20,ap:1.6,blur:18,exp:1,shift:[0,0]},{t:1.3,pos:[1.8,1.4,-15.5],tgt:[0,.3,2],roll:.08,fov:57,focus:12,ap:2,blur:18,exp:1,shift:[0,0]},{t:2.1,pos:[.9,3,-12.8],tgt:[0,.5,3.6],roll:.02,fov:58,focus:12,ap:3.4,blur:22,exp:1,shift:[0,0]},{t:2.6,pos:[.45,3.6,-12],tgt:[0,.5,4],roll:-.004,fov:58,focus:13,ap:4,blur:24,exp:1,shift:[0,0]},{t:3,pos:[.5,3.5,-12.2],tgt:[0,.5,4],roll:0,fov:58,focus:13,ap:4,blur:24,exp:1,shift:[0,0]}];function Be(t,e,r){let o=J(Gt,Gt+2.2,e);return o>0&&Ot(t,Math.sin(r*.13)*.32*o,Math.sin(r*.09+1.2)*.16*o,Math.sin(r*.071)*.22*o,.15),t}var Ue=[{p:[0,0,0],r:.2,a:{dark:.18,light:.12},ink:4},{p:[4.5,.5,16],r:.32,a:{dark:.05,light:.035},ink:0},{p:[-4.5,-.5,16],r:.32,a:{dark:.05,light:.035},ink:2}],We=t=>({y:.04*t,s:1+.05*t});function le(){let t=Ct(Nt);return{N:26e3,T:Gt,glsl:Ge,gain:{dark:.95,light:.9},composite:{dark:[2.6,.35],light:[2.4,0]},trail:{time:.3,width:.75,alpha:{dark:.55,light:.5}},vignette:{dark:.55,light:.3},fog:[9,.042,.9,2.6],layout(e){t=Ct(e<=0?Nt:e>=1?fe:ue(Nt,fe,e))},glows(e){let r=J(.15,1.7,e);return Ue.map(o=>({...o,a:{dark:o.a.dark*r,light:o.a.light*r}}))},pose(e,r,o,a){return t(r,e),Ot(e,a[0]*.6,a[1]*.32,0,.18),Be(e,r,o)}}}var co=window.matchMedia("(prefers-reduced-motion: reduce)");function ft(t,e,r,o){let a=t.x-e,i=Math.exp(-r*o),u=t.v+r*a;return t.x=e+(a+u*o)*i,t.v=(t.v-r*u*o)*i,Math.abs(t.x-e)+Math.abs(t.v)*.05}var me="scene-quality",$e=2560*1600,Bt=[1,1,.5,.25,.125,.0625,.03125,.03125],He=[1,1,1,.85,.75,.65,.55,.4],j=8,qe=t=>Math.min(2.8,(1/Bt[t])**.3),je=t=>Math.min(2.6,(1/Bt[t])**.32),he=2,Xe=45,Ke=420,St=1/30,pe=12,Ye=["red","red-2","blue","blue-2","purple","dust"],Qe=new Set(["Shift","Control","Alt","Meta","CapsLock","Fn","OS"]),ve=t=>{try{return t(sessionStorage)}catch{return null}},lt=t=>{try{performance.mark("scene:"+t)}catch{}};function Ze(t){let e=String(t||"").trim(),r=/^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(e);if(r){let o=r[1].length===3?r[1].replace(/./g,"$&$&"):r[1];return[0,2,4].map(a=>parseInt(o.slice(a,a+2),16)/255)}return r=/^rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)/i.exec(e),r?[r[1],r[2],r[3]].map(o=>G(parseFloat(o)/255,0,1)):null}function Je(t){let e=t.getExtension("WEBGL_debug_renderer_info"),r=e?t.getParameter(e.UNMASKED_RENDERER_WEBGL):"";return/swiftshader|llvmpipe|softpipe|software|basic render/i.test(String(r))}var de=()=>({only:0,n:0,rects:new Float32Array(32),feather:new Float32Array(8),veil:new Float32Array(4),veil2:new Float32Array(4)});function xe(t,e,r,o,a){t.rects.fill(0),t.feather.fill(0),t.only=e?1:0,t.n=e?Math.min(8,e.length):0;for(let u=0;u<t.n;u++){let f=e[u];t.rects.set([f.x0*o,a-f.y1*o,f.x1*o,a-f.y0*o],u*4),t.feather[u]=(f.f??120)*o}let i=r||{};t.veil.set([(i.colX??0)*o,i.colS??0,a-(i.bottomY??0)*o,i.bottomS??0]),t.veil2.set([(i.topH??0)*o,i.topS??0,(i.f??160)*o,a])}function to(t,e={}){let r=document.createElement("canvas");r.setAttribute("aria-hidden","true");let o=r.getContext("webgl2",{alpha:!1,antialias:!1,depth:!1,stencil:!1,premultipliedAlpha:!0,preserveDrawingBuffer:!1,powerPreference:"high-performance"});if(!o)return null;let a=ve(s=>s.getItem(me));if(a===null&&Je(o))return o.getExtension("WEBGL_lose_context")?.loseContext(),null;let i=le(),u=i.T,f=u+2.2,c=e.reduced||window.matchMedia("(prefers-reduced-motion: reduce)"),m=zt(o,i.glsl),h=!1,A=!1,T=!1,d=!1,L=G(Math.round(+a||0),0,j),N=!1,V=1,k=1,p=1,w=1,y=1,_=1,U=1,n=1,l=0,R=0,E=!1,g=!1,M=pe,x=e.intro&&!c.matches?0:f,W=null,Y=!1,mt=x<u,S={x:{x:0,v:0},y:{x:0,v:0},tx:0,ty:0},nt={x:1,v:0,t:1},it={x:1,v:0,t:1},P={W:p,H:w,OW:V,OH:k,dpr:y,light:0,n:0,vignette:.5,seed:0,comp:[1,0],bg:new Float32Array(3),inks:new Float32Array(18),glows:new Float32Array(bt*4),glowInks:new Float32Array(bt*3),bgMask:de(),views:[]},Ut=[],be=s=>Ut[s]||(Ut[s]={VP:new Float32Array(16),VPp:new Float32Array(16),focal:1,gain:1,time:new Float32Array(4),lens:new Float32Array(4),fog:new Float32Array(4),trail:new Float32Array(3),params:new Float32Array(4),mask:de()}),X="dark",Tt=[],$={frames:0,js:[],level:L,vertices:0},Wt=[],K=(s,v,b,F)=>{s.addEventListener(v,b,F),Wt.push([s,v,b,F])},ht=()=>x<u,Et=()=>Math.max(64,Math.round(i.N*Bt[Math.min(L,j-1)]));function gt(){let s=getComputedStyle(t),v=(F,D)=>Ze(s.getPropertyValue(F))||D,b=s.getPropertyValue("--scene-ink").trim()==="ink";X=b?"light":"dark",P.light=b?1:0,P.bg.set(v("--scene-bg",b?[1,.988,.941]:[.063,.059,.059])),Ye.forEach((F,D)=>P.inks.set(v(`--scene-${F}`,[.55,.5,.75]),D*3))}function pt(){let s=t.getBoundingClientRect(),v=window.devicePixelRatio||1,b=L>=1?Math.min(1,v):Math.min(2,v);b=Math.min(b,Math.sqrt($e/Math.max(1,s.width*s.height)));let F=Math.max(1,Math.round(s.width*b)),D=Math.max(1,Math.round(s.height*b)),ot=He[Math.min(L,j-1)],dt=Math.max(1,Math.round(F*ot)),xt=Math.max(1,Math.round(D*ot));return _=Math.max(1,s.width),U=Math.max(1,s.height),n=_/U,dt===p&&xt===w&&F===V&&D===k?!1:(V=F,k=D,p=dt,w=xt,y=p/_,r.width=V,r.height=k,i.layout(1-J(.62,1.25,n)),!0)}function Le(){let s=x,v=M,b=[S.x.x,S.y.x],F={it:s,ft:v,T:u,W:_,H:U,theme:X},D=e.views?e.views(F):[{id:"hero"}],ot=1-nt.x,dt=G(it.x,0,1),xt=Et();P.W=p,P.H=w,P.OW=V,P.OH=k,P.dpr=y,P.n=xt,P.vignette=e.vignette?e.vignette(X,U):i.vignette[X],P.comp=i.composite[X],P.seed=v*60%97,P.glows.fill(0),P.views.length=0;let wt=0;Tt=[],D.forEach((B,_e)=>{let I=be(_e),C=B.pose,at=B.pose;C||(C=i.pose({},s,v,b),at=i.pose({},s-St,v-St,b));for(let z of C===at?[C]:[C,at])z.focus=O(z.focus,1.6,ot),z.ap=O(z.ap,7,ot),z.blur=O(z.blur,15,ot);Dt(I.VP,C,n),at===C?I.VPp.set(I.VP):Dt(I.VPp,at,n);let te=(C.exp??1)*dt,_t=B.trail||i.trail;I.focal=.5*w/Math.tan(C.fov*Math.PI/360),I.gain=i.gain[X]*te*je(Math.min(L,j-1)),I.time.set([v,s,v-St,s-St]),I.lens.set([C.focus,C.ap*y,C.blur*y,y*qe(Math.min(L,j-1))]),I.fog.set(i.fog),I.trail.set([_t.time,_t.width,_t.alpha[X]]),I.params.set([0,0,B.form||0,0]),xe(I.mask,B.rect?[B.rect]:null,B.veil,y,w),P.views.push(I);for(let z of B.glows||i.glows(s)){let Pt=wt<bt&&ce(I.VP,z.p,p,w);Pt&&(P.glows.set([Pt[0],Pt[1],z.r*w,z.a[X]*te],wt*4),P.glowInks.set(P.inks.subarray(z.ink*3,z.ink*3+3),wt*3),wt++)}Tt.push({id:B.id??null,pos:C.pos.map(z=>Math.round(z*1e3)/1e3)})});let ke=D.map(B=>B.rect).filter(Boolean);return xe(P.bgMask,e.views?ke:null,D[0]?.veil,y,w),{it:s,T:u}}function tt(){if(!h||T)return 0;let s=performance.now(),v=Le();$.vertices=m.draw(P),d||(d=!0,t.append(r),lt(ht()?"first-frame:intro":"first-frame"),requestAnimationFrame(()=>{!T&&!A&&t.classList.add("is-shown")})),e.onFrame?.(v);let b=performance.now()-s;return $.frames++,$.js.push(b),$.js.length>600&&$.js.shift(),b}function $t(s){mt&&(mt=!1,lt("intro-end:"+s),e.onIntroEnd?.(s))}function Se(){ht()&&$t("stopped"),x=Math.max(x,f),W=null;for(let s of[nt,it])s.x=s.t,s.v=0;c.matches&&(S.tx=S.ty=0),S.x.x=S.tx,S.y.x=S.ty,S.x.v=S.y.v=0}function Q(){!h||T||(Se(),tt())}let Z=()=>h&&!T&&!E&&!N&&!c.matches&&L<j,Te=()=>e.visible?e.visible():!0,Ht=()=>Z()&&!document.hidden&&Te(),st=[],qt=0;function Ee(s){if(L>=j-1||qt++<he||s>1e3||(st.push(s),st.length<(qt<=he+8?4:20)))return;let v=st.slice().sort((F,D)=>F-D)[st.length>>1];if(st.length=0,v<=Xe)return;let b=L===0&&(window.devicePixelRatio||1)<=1?1:L;L=Math.min(j-1,Math.max(L+1,b+Math.max(1,Math.ceil(Math.log2(v/28))))),$.level=L,ve(F=>F.setItem(me,String(L))),lt(`quality:${L}:${Math.round(v)}ms`),pt(),e.onQuality?.(L)}function ge(s){if(!(x>=f)){if(W){let v=se((performance.now()-W.at)/Ke);x=O(W.from,u,v),v>=1&&(W=null)}else x=Math.min(f,x+s);x>=u&&$t(Y?"skipped":"played")}}function jt(s){if(l=0,!Ht()){R=0,Z()&&!document.hidden&&!g&&(g=!0,tt());return}g=!1;let v=R?s-R:0,b=R?Math.min(.25,v/1e3):1/60;R=s,ge(b),M+=Math.min(.05,b),ft(nt,nt.t,6,b),ft(it,it.t,6,b),ft(S.x,S.tx,3.2,b),ft(S.y,S.ty,3.2,b),tt(),v&&Ee(v),Ht()&&(l=requestAnimationFrame(jt))}let H=()=>{!l&&h&&Z()&&!document.hidden&&(l=requestAnimationFrame(jt))},et=()=>{l&&cancelAnimationFrame(l),l=0,R=0},Mt=()=>Z()?H():Q(),vt=0,Me=()=>{vt||(vt=requestAnimationFrame(()=>{vt=0,Q()}))},Xt=()=>{ht()&&!W&&(W={from:x,at:performance.now()},Y=!0,lt("intro-skip"))},Rt=0;function At(){if(Rt=0,T)return;let s=m.poll();if(s==="pending"){Rt=requestAnimationFrame(At);return}if(s==="failed"){Kt("shaders");return}h=!0,lt("ready"),gt(),pt(),t.classList.add("is-live"),e.onQuality?.(L),Z()?(tt(),H()):Q(),e.onReady?.()}function Kt(s){A=!0,h=!1,et(),t.classList.remove("is-live","is-shown"),e.onFail?.(s)}gt(),At();let Re=s=>{(s.type!=="keydown"||!Qe.has(s.key))&&Xt()},Ae=requestAnimationFrame(()=>{if(!T)for(let s of["keydown","pointerdown","wheel","touchstart"])K(window,s,Re,{passive:!0})}),Yt=(s,v)=>{c.matches||(S.tx=G(s/window.innerWidth*2-1,-1,1),S.ty=G(-(v/window.innerHeight*2-1),-1,1),H())},Qt=()=>{S.tx=0,S.ty=0,H()};K(window,"pointermove",s=>{s.pointerType!=="touch"&&Yt(s.clientX,s.clientY)},{passive:!0}),K(window,"touchmove",s=>{let v=s.touches[0];v&&Yt(v.clientX,v.clientY)},{passive:!0}),K(window,"touchend",Qt,{passive:!0}),K(document,"pointerleave",Qt),K(document,"visibilitychange",()=>document.hidden?et():H());let Zt=()=>c.matches?(et(),Q()):H();c.addEventListener("change",Zt);let kt=0,Jt=new ResizeObserver(()=>{clearTimeout(kt),kt=setTimeout(()=>{!h||!pt()||(Z()?l||(tt(),H()):Q())},60)});return Jt.observe(t),K(r,"webglcontextlost",s=>{s.preventDefault(),Kt("context lost")}),K(r,"webglcontextrestored",()=>{T||(m=zt(o,i.glsl),A=!1,At())}),{setScroll(s){(+s||0)*window.innerHeight>8&&Xt(),Z()?H():h&&Me()},setFocus(s){nt.t=G(+s,0,1),Mt()},setIntensity(s){it.t=G(+s,0,1),Mt()},pause(){N=!0,et(),Q()},resume(){N=!1,Mt()},restyle(){gt(),l||Q()},destroy(){T=!0,et(),cancelAnimationFrame(Rt),cancelAnimationFrame(Ae),cancelAnimationFrame(vt),clearTimeout(kt);for(let[s,v,b,F]of Wt)s.removeEventListener(v,b,F);c.removeEventListener("change",Zt),Jt.disconnect(),m.dispose(),o.getExtension("WEBGL_lose_context")?.loseContext(),r.remove(),t.classList.remove("is-live","is-shown")},get failed(){return A},get level(){return L},seek(s,v={}){if(!h)return!1;et(),E=!0,x=Math.min(Math.max(0,s),f),M=pe+s,W=null;let b=v.ptr||[0,0];return S.x.x=S.tx=b[0],S.y.x=S.ty=b[1],S.x.v=S.y.v=0,pt(),tt(),!0},live(){E=!1,H()},clock:()=>({introT:x,flowT:M,introRunning:ht(),level:L,density:Et()/i.N,frames:$.frames,views:Tt}),stats:()=>({...$,level:L,js:$.js.slice(),N:Et(),perParticle:It,composite:m.composite})}}var we=[{a:{pos:[12,6.6,18],tgt:[0,.4,14],hfov:60,focus:12.5,ap:.6,blur:8,roll:0},b:{pos:[12,5.2,18],tgt:[0,-.3,14]}},{a:{pos:[9,2.1,8],tgt:[5.2,1.1,19],hfov:58,focus:10,ap:.6,blur:8,roll:.06},b:{pos:[9,1,8],tgt:[5.2,.6,19],roll:.04}},{a:{pos:[-4.4,-1.9,7.5],tgt:[-6.6,.4,18.5],hfov:50,focus:11,ap:.6,blur:8,roll:-.08},b:{pos:[-4.4,-3,7.5],tgt:[-6.6,-.1,18.5],roll:-.06}},{form:1,a:{pos:[0,1.6,15],tgt:[0,0,0],hfov:58,focus:15,ap:.8,blur:10,roll:.02},b:{},portrait:{a:{pos:[0,1.4,15.5],tgt:[0,0,0],hfov:46,focus:15.5,ap:.8,blur:10,roll:.02},b:{}},glows:eo,trail:{time:1.1,width:.7,alpha:{dark:.55,light:.5}}}];function eo(t){let e=Math.PI/q.w,r=(q.twist*t/q.w%e+e)%e;return[-1,0,1].map(o=>({p:[r+(o-.5)*e,0,0],r:.13,a:{dark:.08,light:.055},ink:4}))}var ye=(t,e,r)=>t.map((o,a)=>O(o,e[a],r));function oo(t,e,r){let o={pos:ye(t.pos,e.pos??t.pos,r),tgt:ye(t.tgt,e.tgt??t.tgt,r)};for(let a of["hfov","roll","focus","ap","blur"])o[a]=O(t[a]??0,e[a]??t[a]??0,r);return o.exp=1,o}function ro({hero:t,frames:e,header:r,reduced:o}){let a=t.closest("main")||document.body,i=p=>t.querySelector(p),u={role:i(".hero__role"),lede:i(".hero__lede"),cta:i(".hero__cta"),cue:i(".cue")},f=t.nextElementSibling,c=null,m=p=>{let w=0,y=0;for(let _=p;_;_=_.offsetParent)w+=_.offsetLeft,y+=_.offsetTop;return{x0:w,y0:y,x1:w+p.offsetWidth,y1:y+p.offsetHeight}};function h(){let p=document.documentElement.clientWidth;c={W:p,desk:p>=960,header:r?r.offsetHeight:64,hero:m(t),first:f?m(f).y0:m(t).y1,windows:e.map(m),copy:Object.fromEntries(Object.entries(u).filter(([,w])=>w).map(([w,y])=>[w,m(y)]))}}let A=()=>window.scrollY,T=p=>J(0,Math.max(1,c.first-.32*p),A());function d(p,w){let y=c.copy;return c.desk?{colX:Math.max(y.lede?.x1??0,y.cta?.x1??0,y.role?.x1??0)+24,colS:.9,bottomY:(y.cue?.y0??c.hero.y1-80)-20-p,bottomS:.82,topH:c.header+12,topS:.85,f:Math.max(140,.12*w)}:{topH:Math.max(c.header+8,(y.role?.y1??0)+16-p),topS:.9,bottomY:(y.lede?.y0??.6*c.hero.y1)-18-p,bottomS:.93,f:90}}function L(p){c||h();let w=A(),{W:y,H:_}=p,U=[];return c.hero.y1-w>0&&U.push({id:"hero",rect:{x0:-400,y0:c.hero.y0-400-w,x1:y+400,y1:c.hero.y1-w,f:.24*_},veil:d(w,y)}),c.windows.forEach((n,l)=>{let R=n.y0-w,E=n.y1-w,g=E-R;if(g<=0||E<0||R>_)return;let M=we[l%we.length],x=!c.desk&&M.portrait?M.portrait:M,W=G(((R+E)/2-_/2)/(_/2+g/2),-1,1),Y=oo(x.a,x.b,o.matches?.5:(1-W)/2),mt=Y.hfov*(c.desk||M.portrait?1:.74);Y.fov=2*Math.atan(Math.tan(mt*Math.PI/360)/(y/_))*180/Math.PI,Y.shift=[0,1-(R+E)/_];let S=typeof M.glows=="function"?M.glows(p.ft):M.glows;U.push({id:`w${l+1}`,rect:{x0:-400,y0:R,x1:y+400,y1:E,f:.34*g},pose:Y,form:M.form||0,glows:S,trail:M.trail})}),U}let N=()=>{c||h();let p=A(),w=window.innerHeight;return c.hero.y1-p>0||c.windows.some(y=>y.y1-p>0&&y.y0-p<w)},V=(p,w)=>O(p==="light"?.3:.55,0,T(w));h();let k=new ResizeObserver(h);return k.observe(a),window.addEventListener("resize",h),{views:L,visible:N,vignette:V,layout:()=>c,update:h,destroy(){k.disconnect(),window.removeEventListener("resize",h)}}}export{j as STILL,ro as createWindows,to as mount,We as nameMotion};
