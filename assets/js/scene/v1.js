// The world of the home page, and V1 "Pass-through", its landing.
//
// Two currents, red (the red team) and blue (the blue team), sweep in from far upstream as wide streams of helical
// flow lines, converge and twist into a tight braid, red and blue still, with a purple tinge where they meet; further
// down, the two strands fuse into one purple cord. The fuse point drifts slowly along the braid, and around it the
// strands tangle: they wind round each other unevenly, wander and fray a little. The knot is at the origin, the braid
// runs down -z, the red arm comes in from +x and the blue one from -x. param (uP.w) is 1 on narrow layouts, where the
// copy's veil covers the braid further down, so the strands fuse nearer the knot (FUSE).
// - Startup: every particle starts scattered (4 to 11 units from its place) and converges into the flow, fading in
//   on the way, staggered by its distance from the knot, so the braid draws itself from the knot outward along both
//   arms. It is driven by the intro clock, so a page without the intro shows the assembled flow.
// - The camera (T = 3 s): alongside the tight rope downstream, gliding toward the knot while the braid forms, then
//   rising and swinging out to the resting frame: a sideways "Y" right of the copy on landscape screens, an upright
//   one between the name and the copy on portrait screens.
// - The strands (uP.z = 1, the last window): the two currents as one calm braid seen from the side, along x. Each
//   strand is a wide, soft cloud of fibres around its centreline; red stays red and blue stays blue between the
//   crossings, and purple glows only where they cross. Toward +x they zip into one purple rope: the helix narrows and
//   both turn purple. The join follows the window across the screen (param, uP.w: where the join is along x, from
//   zipJoin()), from beyond the right edge to past the middle (ZIP), so the strands zip together as the page scrolls
//   on. The flow along them (+x, into the join) and the twist are slow (STRANDS), and both are functions
//   of the time alone.
//
// Every particle is derived from its id and the time (see gl.js for the Pt struct, hash and uniforms), so there are
// no buffers. Ink slots: 0 red, 1 red (second), 2 blue, 3 blue (second), 4 purple, 5 dust.
import { makePath, blendKeys, rig, smooth, mix } from "./math.js";

// The strands' braid: angular frequency along x (crossings every pi / w units), twist (rad/s, the crossings drift
// along +x at twist / w units/s), flow along the strands (units/s), helix radius and length.
export const STRANDS = { w: 0.55, twist: 0.12, flow: 0.3, radius: 1.25, length: 46 };
// The landing's fuse point (z): at rest on wide and on narrow layouts, and the half-width of the fuse.
const FUSE = { z: -4.3, narrow: -1.5, half: 1.4 };
// The strands' join: it spans x - j in [a, b], with j going from enter to leave as the window crosses the screen. On
// narrow screens the view is narrower (about x = -6.6 .. 6.6 against -8.3 .. 8.3) and the band crosses it sooner, so
// the join starts just inside the right edge and still leaves the left edge apart as the band goes.
const ZIP = { a: -2, b: 3.5, enter: 9, leave: -5, narrow: { enter: 6, leave: -5 } };
// Where the join is (j, the strands' param) for the window at k (0 entering .. 1 leaving), and how far the strands
// have joined at x for it (0 apart .. 1 one rope): the shader's zip(), for the crossings' glows (windows.js).
export const zipJoin = (k, narrow) => { const z = narrow ? ZIP.narrow : ZIP; return mix(z.enter, z.leave, k); };
export const zipAt = (x, j) => smooth(ZIP.a, ZIP.b, x - j);
const f1 = (v) => v.toFixed(4);
const GLSL = `
const float ZT=44.,ZL=88.;
const float SW=${f1(STRANDS.w)},ST=${f1(STRANDS.twist)},SV=${f1(STRANDS.flow)},SA=${f1(STRANDS.radius)},SL=${f1(STRANDS.length)};
const float FZ=${f1(FUSE.z)},FN=${f1(FUSE.narrow)},FH=${f1(FUSE.half)};
const float ZA=${f1(ZIP.a)},ZB=${f1(ZIP.b)};
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
}`;

const T = 3;
// Camera keys, landscape (L) and portrait (P), with the same times. ap/blur: depth of field (aperture and maximum
// blur, in CSS px); exp: exposure; shift: lens shift in NDC units.
const L = [
  { t: 0, pos: [2.2, 1.0, -26], tgt: [0.4, 0.2, -4], roll: 0.06, fov: 42, focus: 18, ap: 1.6, blur: 18, exp: 0.95, shift: [0.1, 0] },
  { t: 0.3, pos: [2.3, 1.0, -26.8], tgt: [0.4, 0.2, -4.4], roll: 0.065, fov: 41.6, focus: 18, ap: 1.6, blur: 18, exp: 1, shift: [0.1, 0] },
  { t: 1.3, pos: [3.4, 1.6, -13], tgt: [0.2, 0.1, 0], roll: 0.1, fov: 42, focus: 10, ap: 2, blur: 18, exp: 1, shift: [0.15, 0] },
  { t: 2.1, pos: [6.0, 4.0, -9.6], tgt: [0, 0, -0.2], roll: 0.03, fov: 40, focus: 11, ap: 3.5, blur: 22, exp: 1, shift: [0.24, 0.03] },
  { t: 2.6, pos: [7.6, 5.15, -11.6], tgt: [0, 0, -0.5], roll: -0.004, fov: 39.6, focus: 13.5, ap: 4.2, blur: 26, exp: 1, shift: [0.26, 0.03] },
  { t: 3.0, pos: [7.4, 5.0, -11.3], tgt: [0, 0, -0.5], roll: 0, fov: 40, focus: 13.5, ap: 4.2, blur: 26, exp: 1, shift: [0.26, 0.03] },
];
const P = [
  { t: 0, pos: [1.4, 0.8, -27], tgt: [0.2, 0.3, 0], roll: 0.05, fov: 56, focus: 20, ap: 1.6, blur: 18, exp: 0.95, shift: [0, 0] },
  { t: 0.3, pos: [1.45, 0.8, -27.8], tgt: [0.2, 0.3, 0], roll: 0.055, fov: 55.6, focus: 20, ap: 1.6, blur: 18, exp: 1, shift: [0, 0] },
  { t: 1.3, pos: [1.8, 1.4, -15.5], tgt: [0, 0.3, 2], roll: 0.08, fov: 57, focus: 12, ap: 2, blur: 18, exp: 1, shift: [0, 0] },
  { t: 2.1, pos: [0.9, 3.0, -12.8], tgt: [0, 0.5, 3.6], roll: 0.02, fov: 58, focus: 12, ap: 3.4, blur: 22, exp: 1, shift: [0, 0] },
  { t: 2.6, pos: [0.45, 3.6, -12.0], tgt: [0, 0.5, 4], roll: -0.004, fov: 58, focus: 13, ap: 4, blur: 24, exp: 1, shift: [0, 0] },
  { t: 3.0, pos: [0.5, 3.5, -12.2], tgt: [0, 0.5, 4], roll: 0, fov: 58, focus: 13, ap: 4, blur: 24, exp: 1, shift: [0, 0] },
];

// A slow drift once the intro has settled (it fades in over 2.2 s after the end), along the camera's own axes.
function idleDrift(pose, it, ft) {
  const k = smooth(T, T + 2.2, it);
  if (k > 0) rig(pose, Math.sin(ft * 0.13) * 0.32 * k, Math.sin(ft * 0.09 + 1.2) * 0.16 * k, Math.sin(ft * 0.071) * 0.22 * k, 0.15);
  return pose;
}

// Soft glows behind the knot and the two arms: world point, radius (share of the frame height), strength, ink.
const GLOWS = [
  { p: [0, 0, 0], r: 0.2, a: { dark: 0.18, light: 0.12 }, ink: 4 },
  { p: [4.5, 0.5, 16], r: 0.32, a: { dark: 0.05, light: 0.035 }, ink: 0 },
  { p: [-4.5, -0.5, 16], r: 0.32, a: { dark: 0.05, light: 0.035 }, ink: 2 },
];

// The name's intro motion for k = 1 (start) .. 0 (rest): a lift (em) and a scale, transform only. k = 1 is the
// first-paint state in home.css, so the hand-over is seamless.
export const nameMotion = (k) => ({ y: 0.04 * k, s: 1 + 0.05 * k });

export function createWorld() {
  let path = makePath(L);
  return {
    N: 26000,
    T,
    glsl: GLSL,
    gain: { dark: 0.95, light: 0.9 },
    // the composite: coverage gain and the dark overdrive (a dense core may rise to 1 + o times its ink)
    composite: { dark: [2.6, 0.35], light: [2.4, 0] },
    trail: { time: 0.3, width: 0.75, alpha: { dark: 0.55, light: 0.5 } },
    vignette: { dark: 0.55, light: 0.3 },
    // depth fog: [start, density, near fade from, near fade to]
    fog: [9, 0.042, 0.9, 2.6],
    // portrait: 0 (landscape) .. 1 (portrait), from the canvas's aspect ratio
    layout(portrait) {
      path = makePath(portrait <= 0 ? L : portrait >= 1 ? P : blendKeys(L, P, portrait));
    },
    // the knot's glow grows with the assembly, rather than waiting there at full strength
    glows(it) {
      const k = smooth(0.15, 1.7, it);
      return GLOWS.map((g) => ({ ...g, a: { dark: g.a.dark * k, light: g.a.light * k } }));
    },
    // The landing's camera at intro time it and flow time ft, with the pointer ptr in -1..1.
    pose(out, it, ft, ptr) {
      path(it, out);
      rig(out, ptr[0] * 0.6, ptr[1] * 0.32, 0, 0.18);
      return idleDrift(out, it, ft);
    },
  };
}
