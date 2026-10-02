var It="bool bad(float x){return (floatBitsToUint(x)&0x7f800000u)==0x7f800000u;}",ne=`#version 300 es
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
`,zt=`
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
`,Ft="gl_Position=vec4(-9.,-9.,0.,1.);",Fe=t=>`${ne}
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
  if(d<.05||al<.0015){${Ft}vQ=vec2(0.);vS=vec3(1.);vC=vec4(0.);return;}
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
  if(bad(px.x+px.y+hl+re+blur+al+a.c.x+a.c.y+a.c.z)){${Ft}vQ=vec2(0.);vS=vec3(1.);vC=vec4(0.);return;}
  vQ=vec2(cr.x*hl,cr.y*re);
  vS=vec3(L*.5,re,smoothstep(1.6*uDpr,7.*uDpr,blur));
  vC=vec4(a.c*al,al);
  gl_Position=vec4(px/uRes*2.-1.,0.,1.);
}`,Ie=`#version 300 es
precision highp float;
${zt}
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
}`,rt=5,ze=t=>`${ne}
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
  vV=0.;vC=vec4(0.);
  // A point at or behind the near plane is culled. A point that shows nothing is put on the trail's centreline, with
  // no width: a strip that shows nothing then has no area, and one that shows in part tapers to that point. (Culled,
  // it would stretch a sliver from the particle across the screen to the cull point.)
  vec2 sa=(ca.xy/ca.w*.5+.5)*uRes;
  if(!(d>=.05)||bad(sa.x+sa.y)){${Ft}return;}
  if(!(cb.w>=.05)||!(al>=.001)){gl_Position=vec4(sa/uRes*2.-1.,0.,1.);return;}
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
  vec2 px=sa+nr*side*re;
  if(bad(px.x+px.y+al+a.c.x+a.c.y+a.c.z)){gl_Position=vec4(sa/uRes*2.-1.,0.,1.);return;}
  vV=side;
  vC=vec4(a.c*al,al);
  gl_Position=vec4(px/uRes*2.-1.,0.,1.);
}`,Ve=`#version 300 es
precision highp float;
${zt}
in float vV;
in vec4 vC;
uniform float uAccS;
out vec4 o;
void main(){
  o=vC*(exp(-vV*vV*2.6)*shade(gl_FragCoord.xy)*uAccS);
  if(bad(o.r+o.g+o.b+o.a))o=vec4(0.);
}`,re=`#version 300 es
void main(){vec2 p=vec2(float((gl_VertexID<<1)&2),float(gl_VertexID&2));gl_Position=vec4(p*2.-1.,0.,1.);}`,yt=6,Ce=`#version 300 es
precision highp float;
${zt}
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
}`,Vt=4+2*(rt+1),bt=yt,ct=4;function Ct(t,e){let r=[],o=t.getExtension("KHR_parallel_shader_compile"),s=(n,h)=>{let A=t.createProgram();for(let[R,M]of[[t.VERTEX_SHADER,n],[t.FRAGMENT_SHADER,h]]){let S=t.createShader(R);t.shaderSource(S,M),t.compileShader(S),t.attachShader(A,S),r.push(S)}return t.linkProgram(A),A},i={bg:s(re,Ce),trail:s(ze(e),Ve),head:s(Fe(e),Ie),comp:s(re,De)},u=o?null:t.fenceSync(t.SYNC_GPU_COMMANDS_COMPLETE,0);t.flush();let l=t.createVertexArray(),c=!!(t.getExtension("EXT_color_buffer_float")||t.getExtension("EXT_color_buffer_half_float")),f=c?1:.25,m=[],E=[],y=null,v="pending",L=0,B=0;function D(n){let h={},A=t.getProgramParameter(n,t.ACTIVE_UNIFORMS);for(let R=0;R<A;R++){let M=t.getActiveUniform(n,R).name;h[M.replace("[0]","")]=t.getUniformLocation(n,M)}return{p:n,u:h}}function k(){if(v!=="pending")return v;if(o){if(!Object.values(i).every(n=>t.getProgramParameter(n,o.COMPLETION_STATUS_KHR)))return v}else if(u){if(t.getSyncParameter(u,t.SYNC_STATUS)!==t.SIGNALED)return v;t.deleteSync(u),u=null}for(let[n,h]of Object.entries(i))if(!t.getProgramParameter(h,t.LINK_STATUS))return console.warn(`scene: the ${n} program did not link`,t.getProgramInfoLog(h)),v="failed",v;return y=Object.fromEntries(Object.entries(i).map(([n,h])=>[n,D(h)])),v="ready",v}function p(n,h,A,R,M,S){m[n]||(m[n]=t.createTexture(),E[n]=t.createFramebuffer()),t.bindTexture(t.TEXTURE_2D,m[n]),t.texImage2D(t.TEXTURE_2D,0,R,h,A,0,t.RGBA,M,null),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_MIN_FILTER,S),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_MAG_FILTER,S),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_WRAP_S,t.CLAMP_TO_EDGE),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_WRAP_T,t.CLAMP_TO_EDGE),t.bindFramebuffer(t.FRAMEBUFFER,E[n]),t.framebufferTexture2D(t.FRAMEBUFFER,t.COLOR_ATTACHMENT0,t.TEXTURE_2D,m[n],0)}function x(n,h){n===L&&h===B||(L=n,B=h,p(0,Math.ceil(n/ct),Math.ceil(h/ct),t.RGBA8,t.UNSIGNED_BYTE,t.LINEAR),p(1,n,h,c?t.RGBA16F:t.RGBA8,c?t.HALF_FLOAT:t.UNSIGNED_BYTE,t.LINEAR),c&&t.checkFramebufferStatus(t.FRAMEBUFFER)!==t.FRAMEBUFFER_COMPLETE&&(c=!1,f=.25,p(1,n,h,t.RGBA8,t.UNSIGNED_BYTE,t.LINEAR)))}function w(n,h){t.uniform4f(n.u.uMask,h.only,0,h.n,0),t.uniform4fv(n.u.uRects,h.rects),t.uniform1fv(n.u.uRectF,h.feather),t.uniform4fv(n.u.uVeil,h.veil),t.uniform4fv(n.u.uVeil2,h.veil2)}function _(n){x(n.W,n.H),t.bindVertexArray(l),t.disable(t.BLEND),t.bindFramebuffer(t.FRAMEBUFFER,E[0]),t.viewport(0,0,Math.ceil(n.W/ct),Math.ceil(n.H/ct));let h=y.bg;t.useProgram(h.p),t.uniform1f(h.u.uPS,ct),t.uniform2f(h.u.uRes,n.W,n.H),t.uniform3fv(h.u.uBg,n.bg),t.uniform1f(h.u.uLight,n.light),t.uniform4fv(h.u.uG,n.glows),t.uniform3fv(h.u.uGC,n.glowInks),t.uniform1f(h.u.uVig,n.vignette),w(h,n.bgMask),t.drawArrays(t.TRIANGLES,0,3),t.bindFramebuffer(t.FRAMEBUFFER,E[1]),t.viewport(0,0,n.W,n.H),t.clearColor(0,0,0,0),t.clear(t.COLOR_BUFFER_BIT),t.enable(t.BLEND),t.blendFunc(t.ONE,t.ONE),t.blendEquation(t.FUNC_ADD),t.enable(t.SCISSOR_TEST);let A=6;for(let M of n.views){let S=M.mask.box;if(S[2]<=0||S[3]<=0)continue;t.scissor(S[0],S[1],S[2],S[3]);let F=T=>{t.useProgram(T.p),t.uniformMatrix4fv(T.u.uVP,!1,M.VP),T.u.uVPp&&t.uniformMatrix4fv(T.u.uVPp,!1,M.VPp),t.uniform2f(T.u.uRes,n.W,n.H),t.uniform1f(T.u.uFocal,M.focal),t.uniform1f(T.u.uDpr,n.dpr),t.uniform4fv(T.u.uTime,M.time),t.uniform4fv(T.u.uLens,M.lens),t.uniform4fv(T.u.uFog,M.fog),t.uniform1f(T.u.uGain,M.gain),t.uniform3fv(T.u.uInk,n.inks),t.uniform1f(T.u.uN,n.n),t.uniform4fv(T.u.uP,M.params),t.uniform1f(T.u.uAccS,f),w(T,M.mask)};F(y.trail),t.uniform3fv(y.trail.u.uTrail,M.trail),t.drawArraysInstanced(t.TRIANGLE_STRIP,0,2*(rt+1),n.n),F(y.head),t.drawArraysInstanced(t.TRIANGLE_STRIP,0,4,n.n),A+=n.n*Vt}t.disable(t.SCISSOR_TEST),t.bindFramebuffer(t.FRAMEBUFFER,null),t.viewport(0,0,n.OW,n.OH),t.disable(t.BLEND);let R=y.comp;return t.useProgram(R.p),t.activeTexture(t.TEXTURE0),t.bindTexture(t.TEXTURE_2D,m[1]),t.uniform1i(R.u.uAcc,0),t.activeTexture(t.TEXTURE1),t.bindTexture(t.TEXTURE_2D,m[0]),t.uniform1i(R.u.uBgT,1),t.activeTexture(t.TEXTURE0),t.uniform2f(R.u.uOut,n.OW,n.OH),t.uniform1f(R.u.uLight,n.light),t.uniform1f(R.u.uSeed,n.seed),t.uniform3f(R.u.uComp,n.comp[0],n.comp[1],1/f),t.drawArrays(t.TRIANGLES,0,3),A}function W(){u&&t.deleteSync(u);for(let n of Object.values(i))t.deleteProgram(n);for(let n of r)t.deleteShader(n);for(let n of m)t.deleteTexture(n);for(let n of E)t.deleteFramebuffer(n);t.deleteVertexArray(l)}return{poll:k,draw:_,dispose:W,get composite(){return c?"rgba16f":"rgba8"}}}var z=(t,e,r)=>Math.min(r,Math.max(e,t)),G=(t,e,r)=>t+(e-t)*r,J=(t,e,r)=>{let o=z((r-t)/(e-t),0,1);return o*o*(3-2*o)},se=t=>1-Math.pow(1-z(t,0,1),3),Oe=(t,e)=>[t[0]-e[0],t[1]-e[1],t[2]-e[2]],St=(t,e)=>t[0]*e[0]+t[1]*e[1]+t[2]*e[2],ie=(t,e)=>[t[1]*e[2]-t[2]*e[1],t[2]*e[0]-t[0]*e[2],t[0]*e[1]-t[1]*e[0]],ae=t=>{let e=Math.hypot(t[0],t[1],t[2])||1;return[t[0]/e,t[1]/e,t[2]/e]};function ce(t,e,r=0){let o=ae(Oe(e,t)),s=ie(o,[0,1,0]);s=Math.hypot(s[0],s[1],s[2])<1e-4?[1,0,0]:ae(s);let i=ie(s,o);if(r){let u=Math.cos(r),l=Math.sin(r),c=[0,1,2].map(f=>s[f]*u+i[f]*l);i=[0,1,2].map(f=>i[f]*u-s[f]*l),s=c}return{r:s,u:i,f:o}}function Ot(t,e,r,o=.05,s=400){let{r:i,u,f:l}=ce(e.pos,e.tgt,e.roll||0),c=e.pos,f=1/Math.tan(e.fov*Math.PI/360),[m,E]=e.shift||[0,0],y=f/r,v=-(s+o)/(s-o),L=-2*s*o/(s-o),B=[l[0],l[1],l[2],-St(l,c)],D=[[y*i[0],y*i[1],y*i[2],-y*St(i,c)],[f*u[0],f*u[1],f*u[2],-f*St(u,c)],[-v*l[0],-v*l[1],-v*l[2],v*St(l,c)+L],B];for(let k=0;k<4;k++)D[0][k]+=m*B[k],D[1][k]+=E*B[k];for(let k=0;k<4;k++)for(let p=0;p<4;p++)t[k*4+p]=D[p][k];return t}function ue(t,e,r,o){let s=t[0]*e[0]+t[4]*e[1]+t[8]*e[2]+t[12],i=t[1]*e[0]+t[5]*e[1]+t[9]*e[2]+t[13],u=t[3]*e[0]+t[7]*e[1]+t[11]*e[2]+t[15];return u<=.01?null:[(s/u*.5+.5)*r,(i/u*.5+.5)*o,u]}function Ne(t,e){let r=t.length,o=[],s=new Array(r).fill(0);for(let i=0;i<r-1;i++)o[i]=(e[i+1]-e[i])/(t[i+1]-t[i]);for(let i=1;i<r-1;i++)s[i]=o[i-1]*o[i]<=0?0:2*o[i-1]*o[i]/(o[i-1]+o[i]);return i=>{if(i<=t[0])return e[0];if(i>=t[r-1])return e[r-1];let u=0;for(;i>t[u+1];)u++;let l=t[u+1]-t[u],c=(i-t[u])/l,f=c*c,m=f*c;return(2*m-3*f+1)*e[u]+(m-2*f+c)*l*s[u]+(-2*m+3*f)*e[u+1]+(m-f)*l*s[u+1]}}var Dt=(t,e,r,o,s)=>.5*(2*e+(-t+r)*s+(2*t-5*e+4*r-o)*s*s+(-t+3*e-3*r+o)*s*s*s),Ge=["roll","fov","focus","ap","blur","exp"];function Nt(t){let e=t.length,r=Ne(t.map(o=>o.t),t.map((o,s)=>s));return(o,s)=>{let i=r(o),u=Math.min(e-2,Math.max(0,Math.floor(i))),l=i-u,c=t[Math.max(0,u-1)],f=t[u],m=t[u+1],E=t[Math.min(e-1,u+2)];s.pos=[0,1,2].map(v=>Dt(c.pos[v],f.pos[v],m.pos[v],E.pos[v],l)),s.tgt=[0,1,2].map(v=>Dt(c.tgt[v],f.tgt[v],m.tgt[v],E.tgt[v],l));for(let v of Ge)s[v]=Dt(c[v],f[v],m[v],E[v],l);let y=l*l*(3-2*l);return s.shift=[G(f.shift[0],m.shift[0],y),G(f.shift[1],m.shift[1],y)],s}}function fe(t,e,r){return t.map((o,s)=>{let i=e[s],u={t:o.t};for(let l of Object.keys(o)){if(l==="t")continue;let c=o[l],f=i[l];u[l]=Array.isArray(c)?c.map((m,E)=>G(m,f[E],r)):G(c,f,r)}return u})}function Gt(t,e,r,o,s=.25){let{r:i,u,f:l}=ce(t.pos,t.tgt,t.roll||0);for(let c=0;c<3;c++){let f=i[c]*e+u[c]*r+l[c]*o;t.pos[c]+=f,t.tgt[c]+=f*s}return t}var j={w:.55,twist:.12,flow:.3,radius:1.25,length:46},ut=t=>t.toFixed(4),Be=`
const float ZT=44.,ZL=88.;
const float SW=${ut(j.w)},ST=${ut(j.twist)},SV=${ut(j.flow)},SA=${ut(j.radius)},SL=${ut(j.length)};
// 1 below a, 0 above b (smoothstep with its edges reversed is undefined in GLSL, and some drivers take that literally)
float fall(float a,float b,float x){return 1.-smoothstep(a,b,x);}
float twist(float z){return z<0.?1.2*z:1.6*(1.-exp(-z/3.));}
vec3 ctr(float z,float k,out float w,out float S){
  S=pow(max(smoothstep(-1.,26.,z),1e-12),.6);
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
    float rr=w*sqrt(max(-log(1.-.96*h.z),0.))*.5*(1.+1.5*halo);
    float ph=6.2832*h.w+1.7*z*(1.-.65*S);
    o.p=c+vec3(cos(ph),sin(ph),0.)*rr;
    vec3 base=k<.5?mix(uInk[0],uInk[1],h.y*h.y*.8):mix(uInk[2],uInk[3],h.y*.9);
    o.c=mix(base,uInk[4],fall(-2.5,5.,z)*(h.y<.22?.4:.92));
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
Pt strands(uint id,vec4 h,float t){
  Pt o;
  float f=float(id)/uN;
  float k=float(id&1u);
  if(f<.86){
    float x=(fract(h.x+t*SV*(.8+.4*h.y)/SL)-.5)*SL;
    float ph=SW*x-ST*t+k*3.14159265;
    float rr=.6*sqrt(max(-log(1.-.97*h.z),0.));
    float a=6.2832*h.w+1.3*x-.2*t;
    o.p=vec3(x,SA*sin(ph),.9*SA*cos(ph))+vec3(0.,cos(a),sin(a))*rr;
    vec3 base=k<.5?mix(uInk[0],uInk[1],h.y*.6):mix(uInk[2],uInk[3],h.y*.7);
    float s=sin(ph);
    o.c=mix(base,uInk[4],.88*exp(-s*s/.2));
    o.a=.5*(.3+.7*exp(-rr*rr*2.4))*fall(SL*.5-5.,SL*.5,abs(x));
    o.s=.019*(.7+.6*h.z);
  }else if(f<.93){
    float S=3.14159265/SW;
    float x=mod(floor(h.x*8.)*S+ST*t/SW+SL*.5,8.*S)-SL*.5;
    vec3 r=vec3(h.y,h.z,fract(h.w*7.3))-.5;
    o.p=vec3(x,0.,0.)+normalize(r+1e-3)*.75*sqrt(max(-log(1.-.95*fract(h.w*3.7)),0.));
    o.c=mix(uInk[4],k<.5?uInk[0]:uInk[2],.15*h.y);
    o.a=.36*exp(-dot(o.p.yz,o.p.yz)*.6)*fall(SL*.5-5.,SL*.5,abs(x));
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
}`,Ut=3,Bt=[{t:0,pos:[2.2,1,-26],tgt:[.4,.2,-4],roll:.06,fov:42,focus:18,ap:1.6,blur:18,exp:.95,shift:[.1,0]},{t:.3,pos:[2.3,1,-26.8],tgt:[.4,.2,-4.4],roll:.065,fov:41.6,focus:18,ap:1.6,blur:18,exp:1,shift:[.1,0]},{t:1.3,pos:[3.4,1.6,-13],tgt:[.2,.1,0],roll:.1,fov:42,focus:10,ap:2,blur:18,exp:1,shift:[.15,0]},{t:2.1,pos:[6,4,-9.6],tgt:[0,0,-.2],roll:.03,fov:40,focus:11,ap:3.5,blur:22,exp:1,shift:[.24,.03]},{t:2.6,pos:[7.6,5.15,-11.6],tgt:[0,0,-.5],roll:-.004,fov:39.6,focus:13.5,ap:4.2,blur:26,exp:1,shift:[.26,.03]},{t:3,pos:[7.4,5,-11.3],tgt:[0,0,-.5],roll:0,fov:40,focus:13.5,ap:4.2,blur:26,exp:1,shift:[.26,.03]}],le=[{t:0,pos:[1.4,.8,-27],tgt:[.2,.3,0],roll:.05,fov:56,focus:20,ap:1.6,blur:18,exp:.95,shift:[0,0]},{t:.3,pos:[1.45,.8,-27.8],tgt:[.2,.3,0],roll:.055,fov:55.6,focus:20,ap:1.6,blur:18,exp:1,shift:[0,0]},{t:1.3,pos:[1.8,1.4,-15.5],tgt:[0,.3,2],roll:.08,fov:57,focus:12,ap:2,blur:18,exp:1,shift:[0,0]},{t:2.1,pos:[.9,3,-12.8],tgt:[0,.5,3.6],roll:.02,fov:58,focus:12,ap:3.4,blur:22,exp:1,shift:[0,0]},{t:2.6,pos:[.45,3.6,-12],tgt:[0,.5,4],roll:-.004,fov:58,focus:13,ap:4,blur:24,exp:1,shift:[0,0]},{t:3,pos:[.5,3.5,-12.2],tgt:[0,.5,4],roll:0,fov:58,focus:13,ap:4,blur:24,exp:1,shift:[0,0]}];function Ue(t,e,r){let o=J(Ut,Ut+2.2,e);return o>0&&Gt(t,Math.sin(r*.13)*.32*o,Math.sin(r*.09+1.2)*.16*o,Math.sin(r*.071)*.22*o,.15),t}var We=[{p:[0,0,0],r:.2,a:{dark:.18,light:.12},ink:4},{p:[4.5,.5,16],r:.32,a:{dark:.05,light:.035},ink:0},{p:[-4.5,-.5,16],r:.32,a:{dark:.05,light:.035},ink:2}],$e=t=>({y:.04*t,s:1+.05*t});function me(){let t=Nt(Bt);return{N:26e3,T:Ut,glsl:Be,gain:{dark:.95,light:.9},composite:{dark:[2.6,.35],light:[2.4,0]},trail:{time:.3,width:.75,alpha:{dark:.55,light:.5}},vignette:{dark:.55,light:.3},fog:[9,.042,.9,2.6],layout(e){t=Nt(e<=0?Bt:e>=1?le:fe(Bt,le,e))},glows(e){let r=J(.15,1.7,e);return We.map(o=>({...o,a:{dark:o.a.dark*r,light:o.a.light*r}}))},pose(e,r,o,s){return t(r,e),Gt(e,s[0]*.6,s[1]*.32,0,.18),Ue(e,r,o)}}}var uo=window.matchMedia("(prefers-reduced-motion: reduce)");function ft(t,e,r,o){let s=t.x-e,i=Math.exp(-r*o),u=t.v+r*s;return t.x=e+(s+u*o)*i,t.v=(t.v-r*u*o)*i,Math.abs(t.x-e)+Math.abs(t.v)*.05}var he="scene-quality",qe=2560*1600,Wt=[1,1,.5,.25,.125,.0625,.03125,.03125],je=[1,1,1,.85,.75,.65,.55,.4],X=8,Xe=t=>Math.min(2.8,(1/Wt[t])**.3),He=t=>Math.min(2.6,(1/Wt[t])**.32),pe=2,Ke=45,Ye=420,Et=1/30,ve=12,Qe=["red","red-2","blue","blue-2","purple","dust"],Ze=new Set(["Shift","Control","Alt","Meta","CapsLock","Fn","OS"]),de=t=>{try{return t(sessionStorage)}catch{return null}},lt=t=>{try{performance.mark("scene:"+t)}catch{}};function Je(t){let e=String(t||"").trim(),r=/^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(e);if(r){let o=r[1].length===3?r[1].replace(/./g,"$&$&"):r[1];return[0,2,4].map(s=>parseInt(o.slice(s,s+2),16)/255)}return r=/^rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)/i.exec(e),r?[r[1],r[2],r[3]].map(o=>z(parseFloat(o)/255,0,1)):null}function to(t){let e=t.getExtension("WEBGL_debug_renderer_info"),r=e?t.getParameter(e.UNMASKED_RENDERER_WEBGL):"";return/swiftshader|llvmpipe|softpipe|software|basic render/i.test(String(r))}var xe=()=>({only:0,n:0,rects:new Float32Array(32),feather:new Float32Array(8),veil:new Float32Array(4),veil2:new Float32Array(4),box:new Int32Array(4)});function we(t,e,r,o,s,i){t.rects.fill(0),t.feather.fill(0),t.only=e?1:0,t.n=e?Math.min(8,e.length):0;let u=e?s:0,l=e?i:0,c=e?0:s,f=e?0:i;for(let E=0;E<t.n;E++){let y=e[E],v=[y.x0*o,i-y.y1*o,y.x1*o,i-y.y0*o];t.rects.set(v,E*4),t.feather[E]=(y.f??120)*o,u=Math.min(u,v[0]),l=Math.min(l,v[1]),c=Math.max(c,v[2]),f=Math.max(f,v[3])}u=z(Math.floor(u),0,s),l=z(Math.floor(l),0,i),t.box.set([u,l,Math.max(0,z(Math.ceil(c),0,s)-u),Math.max(0,z(Math.ceil(f),0,i)-l)]);let m=r||{};t.veil.set([(m.colX??0)*o,m.colS??0,i-(m.bottomY??0)*o,m.bottomS??0]),t.veil2.set([(m.topH??0)*o,m.topS??0,(m.f??160)*o,i])}function eo(t,e={}){let r=document.createElement("canvas");r.setAttribute("aria-hidden","true");let o=r.getContext("webgl2",{alpha:!1,antialias:!1,depth:!1,stencil:!1,premultipliedAlpha:!0,preserveDrawingBuffer:!1,powerPreference:"high-performance"});if(!o)return null;let s=de(a=>a.getItem(he));if(s===null&&to(o))return o.getExtension("WEBGL_lose_context")?.loseContext(),null;let i=me(),u=i.T,l=u+2.2,c=e.reduced||window.matchMedia("(prefers-reduced-motion: reduce)"),f=Ct(o,i.glsl),m=!1,E=!1,y=!1,v=!1,L=z(Math.round(+s||0),0,X),B=!1,D=1,k=1,p=1,x=1,w=1,_=1,W=1,n=1,h=0,A=0,R=!1,M=!1,S=ve,F=e.intro&&!c.matches?0:l,T=null,Y=!1,mt=F<u,g={x:{x:0,v:0},y:{x:0,v:0},tx:0,ty:0},nt={x:1,v:0,t:1},it={x:1,v:0,t:1},P={W:p,H:x,OW:D,OH:k,dpr:w,light:0,n:0,vignette:.5,seed:0,comp:[1,0],bg:new Float32Array(3),inks:new Float32Array(18),glows:new Float32Array(bt*4),glowInks:new Float32Array(bt*3),bgMask:xe(),views:[]},$t=[],Se=a=>$t[a]||($t[a]={VP:new Float32Array(16),VPp:new Float32Array(16),focal:1,gain:1,time:new Float32Array(4),lens:new Float32Array(4),fog:new Float32Array(4),trail:new Float32Array(3),params:new Float32Array(4),mask:xe()}),H="dark",Lt=[],$={frames:0,js:[],level:L,vertices:0},qt=[],K=(a,d,b,I)=>{a.addEventListener(d,b,I),qt.push([a,d,b,I])},ht=()=>F<u,Tt=()=>Math.max(64,Math.round(i.N*Wt[Math.min(L,X-1)]));function Mt(){let a=getComputedStyle(t),d=(I,O)=>Je(a.getPropertyValue(I))||O,b=a.getPropertyValue("--scene-ink").trim()==="ink";H=b?"light":"dark",P.light=b?1:0,P.bg.set(d("--scene-bg",b?[1,.988,.941]:[.063,.059,.059])),Qe.forEach((I,O)=>P.inks.set(d(`--scene-${I}`,[.55,.5,.75]),O*3))}function pt(){let a=t.getBoundingClientRect(),d=window.devicePixelRatio||1,b=L>=1?Math.min(1,d):Math.min(2,d);b=Math.min(b,Math.sqrt(qe/Math.max(1,a.width*a.height)));let I=Math.max(1,Math.round(a.width*b)),O=Math.max(1,Math.round(a.height*b)),ot=je[Math.min(L,X-1)],dt=Math.max(1,Math.round(I*ot)),xt=Math.max(1,Math.round(O*ot));return _=Math.max(1,a.width),W=Math.max(1,a.height),n=_/W,dt===p&&xt===x&&I===D&&O===k?!1:(D=I,k=O,p=dt,x=xt,w=p/_,r.width=D,r.height=k,i.layout(1-J(.62,1.25,n)),!0)}function Ee(){let a=F,d=S,b=[g.x.x,g.y.x],I={it:a,ft:d,T:u,W:_,H:W,theme:H},O=e.views?e.views(I):[{id:"hero"}],ot=1-nt.x,dt=z(it.x,0,1),xt=Tt();P.W=p,P.H=x,P.OW=D,P.OH=k,P.dpr=w,P.n=xt,P.vignette=e.vignette?e.vignette(H,W):i.vignette[H],P.comp=i.composite[H],P.seed=d*60%97,P.glows.fill(0),P.views.length=0;let wt=0;Lt=[],O.forEach((U,Pe)=>{let V=Se(Pe),N=U.pose,st=U.pose;N||(N=i.pose({},a,d,b),st=i.pose({},a-Et,d-Et,b));for(let C of N===st?[N]:[N,st])C.focus=G(C.focus,1.6,ot),C.ap=G(C.ap,7,ot),C.blur=G(C.blur,15,ot);Ot(V.VP,N,n),st===N?V.VPp.set(V.VP):Ot(V.VPp,st,n);let oe=(N.exp??1)*dt,_t=U.trail||i.trail;V.focal=.5*x/Math.tan(N.fov*Math.PI/360),V.gain=i.gain[H]*oe*He(Math.min(L,X-1)),V.time.set([d,a,d-Et,a-Et]),V.lens.set([N.focus,N.ap*w,N.blur*w,w*Xe(Math.min(L,X-1))]),V.fog.set(i.fog),V.trail.set([_t.time,_t.width,_t.alpha[H]]),V.params.set([0,0,U.form||0,0]),we(V.mask,U.rect?[U.rect]:null,U.veil,w,p,x),P.views.push(V);for(let C of U.glows||i.glows(a)){let Pt=wt<bt&&ue(V.VP,C.p,p,x);Pt&&(P.glows.set([Pt[0],Pt[1],C.r*x,C.a[H]*oe],wt*4),P.glowInks.set(P.inks.subarray(C.ink*3,C.ink*3+3),wt*3),wt++)}Lt.push({id:U.id??null,pos:N.pos.map(C=>Math.round(C*1e3)/1e3)})});let _e=O.map(U=>U.rect).filter(Boolean);return we(P.bgMask,e.views?_e:null,O[0]?.veil,w,p,x),{it:a,T:u}}function tt(){if(!m||y)return 0;let a=performance.now(),d=Ee();$.vertices=f.draw(P),v||(v=!0,t.append(r),lt(ht()?"first-frame:intro":"first-frame"),requestAnimationFrame(()=>{!y&&!E&&t.classList.add("is-shown")})),e.onFrame?.(d);let b=performance.now()-a;return $.frames++,$.js.push(b),$.js.length>600&&$.js.shift(),b}function jt(a){mt&&(mt=!1,lt("intro-end:"+a),e.onIntroEnd?.(a))}function Le(){ht()&&jt("stopped"),F=Math.max(F,l),T=null;for(let a of[nt,it])a.x=a.t,a.v=0;c.matches&&(g.tx=g.ty=0),g.x.x=g.tx,g.y.x=g.ty,g.x.v=g.y.v=0}function Q(){!m||y||(Le(),tt())}let Z=()=>m&&!y&&!R&&!B&&!c.matches&&L<X,Te=()=>e.visible?e.visible():!0,Xt=()=>Z()&&!document.hidden&&Te(),at=[],Ht=0;function Me(a){if(L>=X-1||Ht++<pe||a>1e3||(at.push(a),at.length<(Ht<=pe+8?4:20)))return;let d=at.slice().sort((I,O)=>I-O)[at.length>>1];if(at.length=0,d<=Ke)return;let b=L===0&&(window.devicePixelRatio||1)<=1?1:L;L=Math.min(X-1,Math.max(L+1,b+Math.max(1,Math.ceil(Math.log2(d/28))))),$.level=L,de(I=>I.setItem(he,String(L))),lt(`quality:${L}:${Math.round(d)}ms`),pt(),e.onQuality?.(L)}function ge(a){if(!(F>=l)){if(T){let d=se((performance.now()-T.at)/Ye);F=G(T.from,u,d),d>=1&&(T=null)}else F=Math.min(l,F+a);F>=u&&jt(Y?"skipped":"played")}}function Kt(a){if(h=0,!Xt()){A=0,Z()&&!document.hidden&&!M&&(M=!0,tt());return}M=!1;let d=A?a-A:0,b=A?Math.min(.25,d/1e3):1/60;A=a,ge(b),S+=Math.min(.05,b),ft(nt,nt.t,6,b),ft(it,it.t,6,b),ft(g.x,g.tx,3.2,b),ft(g.y,g.ty,3.2,b),tt(),d&&Me(d),Xt()&&(h=requestAnimationFrame(Kt))}let q=()=>{!h&&m&&Z()&&!document.hidden&&(h=requestAnimationFrame(Kt))},et=()=>{h&&cancelAnimationFrame(h),h=0,A=0},gt=()=>Z()?q():Q(),vt=0,Re=()=>{vt||(vt=requestAnimationFrame(()=>{vt=0,Q()}))},Yt=()=>{ht()&&!T&&(T={from:F,at:performance.now()},Y=!0,lt("intro-skip"))},Rt=0;function At(){if(Rt=0,y)return;let a=f.poll();if(a==="pending"){Rt=requestAnimationFrame(At);return}if(a==="failed"){Qt("shaders");return}m=!0,lt("ready"),Mt(),pt(),t.classList.add("is-live"),e.onQuality?.(L),Z()?(tt(),q()):Q(),e.onReady?.()}function Qt(a){E=!0,m=!1,et(),t.classList.remove("is-live","is-shown"),e.onFail?.(a)}Mt(),At();let Ae=a=>{(a.type!=="keydown"||!Ze.has(a.key))&&Yt()},ke=requestAnimationFrame(()=>{if(!y)for(let a of["keydown","pointerdown","wheel","touchstart"])K(window,a,Ae,{passive:!0})}),Zt=(a,d)=>{c.matches||(g.tx=z(a/window.innerWidth*2-1,-1,1),g.ty=z(-(d/window.innerHeight*2-1),-1,1),q())},Jt=()=>{g.tx=0,g.ty=0,q()};K(window,"pointermove",a=>{a.pointerType!=="touch"&&Zt(a.clientX,a.clientY)},{passive:!0}),K(window,"touchmove",a=>{let d=a.touches[0];d&&Zt(d.clientX,d.clientY)},{passive:!0}),K(window,"touchend",Jt,{passive:!0}),K(document,"pointerleave",Jt),K(document,"visibilitychange",()=>document.hidden?et():q());let te=()=>c.matches?(et(),Q()):q();c.addEventListener("change",te);let kt=0,ee=new ResizeObserver(()=>{clearTimeout(kt),kt=setTimeout(()=>{!m||!pt()||(Z()?h||(tt(),q()):Q())},60)});return ee.observe(t),K(r,"webglcontextlost",a=>{a.preventDefault(),Qt("context lost")}),K(r,"webglcontextrestored",()=>{y||(f=Ct(o,i.glsl),E=!1,At())}),{setScroll(a){(+a||0)*window.innerHeight>8&&Yt(),Z()?q():m&&Re()},setFocus(a){nt.t=z(+a,0,1),gt()},setIntensity(a){it.t=z(+a,0,1),gt()},pause(){B=!0,et(),Q()},resume(){B=!1,gt()},restyle(){Mt(),h||Q()},destroy(){y=!0,et(),cancelAnimationFrame(Rt),cancelAnimationFrame(ke),cancelAnimationFrame(vt),clearTimeout(kt);for(let[a,d,b,I]of qt)a.removeEventListener(d,b,I);c.removeEventListener("change",te),ee.disconnect(),f.dispose(),o.getExtension("WEBGL_lose_context")?.loseContext(),r.remove(),t.classList.remove("is-live","is-shown")},get failed(){return E},get level(){return L},seek(a,d={}){if(!m)return!1;et(),R=!0,F=Math.min(Math.max(0,a),l),S=ve+a,T=null;let b=d.ptr||[0,0];return g.x.x=g.tx=b[0],g.y.x=g.ty=b[1],g.x.v=g.y.v=0,pt(),tt(),!0},live(){R=!1,q()},clock:()=>({introT:F,flowT:S,introRunning:ht(),level:L,density:Tt()/i.N,frames:$.frames,views:Lt}),stats:()=>({...$,level:L,js:$.js.slice(),N:Tt(),perParticle:Vt,composite:f.composite})}}var ye=[{a:{pos:[12,6.6,18],tgt:[0,.4,14],hfov:60,focus:12.5,ap:.6,blur:8,roll:0},b:{pos:[12,5.2,18],tgt:[0,-.3,14]}},{a:{pos:[9,2.1,8],tgt:[5.2,1.1,19],hfov:58,focus:10,ap:.6,blur:8,roll:.06},b:{pos:[9,1,8],tgt:[5.2,.6,19],roll:.04}},{a:{pos:[-4.4,-1.9,7.5],tgt:[-6.6,.4,18.5],hfov:50,focus:11,ap:.6,blur:8,roll:-.08},b:{pos:[-4.4,-3,7.5],tgt:[-6.6,-.1,18.5],roll:-.06}},{form:1,a:{pos:[0,1.6,15],tgt:[0,0,0],hfov:58,focus:15,ap:.8,blur:10,roll:.02},b:{},portrait:{a:{pos:[0,1.4,15.5],tgt:[0,0,0],hfov:46,focus:15.5,ap:.8,blur:10,roll:.02},b:{}},glows:oo,trail:{time:1.1,width:.7,alpha:{dark:.55,light:.5}}}];function oo(t){let e=Math.PI/j.w,r=(j.twist*t/j.w%e+e)%e;return[-1,0,1].map(o=>({p:[r+(o-.5)*e,0,0],r:.13,a:{dark:.08,light:.055},ink:4}))}var be=(t,e,r)=>t.map((o,s)=>G(o,e[s],r));function ro(t,e,r){let o={pos:be(t.pos,e.pos??t.pos,r),tgt:be(t.tgt,e.tgt??t.tgt,r)};for(let s of["hfov","roll","focus","ap","blur"])o[s]=G(t[s]??0,e[s]??t[s]??0,r);return o.exp=1,o}function no({hero:t,frames:e,header:r,reduced:o}){let s=t.closest("main")||document.body,i=p=>t.querySelector(p),u={role:i(".hero__role"),lede:i(".hero__lede"),cta:i(".hero__cta"),cue:i(".cue")},l=t.nextElementSibling,c=null,f=p=>{let x=0,w=0;for(let _=p;_;_=_.offsetParent)x+=_.offsetLeft,w+=_.offsetTop;return{x0:x,y0:w,x1:x+p.offsetWidth,y1:w+p.offsetHeight}};function m(){let p=document.documentElement.clientWidth;c={W:p,desk:p>=960,header:r?r.offsetHeight:64,hero:f(t),first:l?f(l).y0:f(t).y1,windows:e.map(f),copy:Object.fromEntries(Object.entries(u).filter(([,x])=>x).map(([x,w])=>[x,f(w)]))}}let E=()=>window.scrollY,y=p=>J(0,Math.max(1,c.first-.32*p),E());function v(p,x){let w=c.copy;return c.desk?{colX:Math.max(w.lede?.x1??0,w.cta?.x1??0,w.role?.x1??0)+24,colS:.9,bottomY:(w.cue?.y0??c.hero.y1-80)-20-p,bottomS:.82,topH:c.header+12,topS:.85,f:Math.max(140,.12*x)}:{topH:Math.max(c.header+8,(w.role?.y1??0)+16-p),topS:.9,bottomY:(w.lede?.y0??.6*c.hero.y1)-18-p,bottomS:.93,f:90}}function L(p){c||m();let x=E(),{W:w,H:_}=p,W=[];return c.hero.y1-x>0&&W.push({id:"hero",rect:{x0:-400,y0:c.hero.y0-400-x,x1:w+400,y1:c.hero.y1-x,f:.24*_},veil:v(x,w)}),c.windows.forEach((n,h)=>{let A=n.y0-x,R=n.y1-x,M=R-A;if(M<=0||R<0||A>_)return;let S=ye[h%ye.length],F=!c.desk&&S.portrait?S.portrait:S,T=z(((A+R)/2-_/2)/(_/2+M/2),-1,1),Y=ro(F.a,F.b,o.matches?.5:(1-T)/2),mt=Y.hfov*(c.desk||S.portrait?1:.74);Y.fov=2*Math.atan(Math.tan(mt*Math.PI/360)/(w/_))*180/Math.PI,Y.shift=[0,1-(A+R)/_];let g=typeof S.glows=="function"?S.glows(p.ft):S.glows;W.push({id:`w${h+1}`,rect:{x0:-400,y0:A,x1:w+400,y1:R,f:.34*M},pose:Y,form:S.form||0,glows:g,trail:S.trail})}),W}let B=()=>{c||m();let p=E(),x=window.innerHeight;return c.hero.y1-p>0||c.windows.some(w=>w.y1-p>0&&w.y0-p<x)},D=(p,x)=>G(p==="light"?.3:.55,0,y(x));m();let k=new ResizeObserver(m);return k.observe(s),window.addEventListener("resize",m),{views:L,visible:B,vignette:D,layout:()=>c,update:m,destroy(){k.disconnect(),window.removeEventListener("resize",m)}}}export{X as STILL,no as createWindows,eo as mount,$e as nameMotion};
