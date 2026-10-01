// The world of the home page, and V1 "Pass-through", its landing.
//
// Two currents, red (the red team) and blue (the blue team), sweep in from far upstream as wide streams of helical
// flow lines, converge and twist into a tight braid that turns purple where they meet. The knot is at the origin, the
// braid runs down -z, the red arm comes in from +x and the blue one from -x.
// - Startup: every particle starts scattered (4 to 11 units from its place) and converges into the flow, fading in
//   on the way, staggered by its distance from the knot, so the braid draws itself from the knot outward along both
//   arms. It is driven by the intro clock, so a page without the intro shows the assembled flow.
// - The camera (T = 3 s): alongside the tight rope downstream, gliding toward the knot while the braid forms, then
//   rising and swinging out to the resting frame: a sideways "Y" right of the copy on landscape screens, an upright
//   one between the name and the copy on portrait screens.
//
// Every particle is derived from its id and the time (see gl.js for the Pt struct, hash and uniforms), so there are
// no buffers. Ink slots: 0 red, 1 red (second), 2 blue, 3 blue (second), 4 purple, 5 dust.
import { makePath, blendKeys, rig, smooth } from "./math.js";

const GLSL = `
const float ZT=44.,ZL=88.;
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
Pt particle(uint id,vec4 h,float t,float it){
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
