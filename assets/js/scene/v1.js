// V1 "Pass-through": two currents (love and foam/pine) sweep in from far upstream as wide streams of helical flow
// lines, converge and twist into a tight braid that turns iris where they meet. The camera starts far down the
// braid, flies up it and through the iris knot (a membrane of particles that bursts as the camera passes, at about
// 1.4 s), out between the two opening arms, then recoils back to rest beside the braid, looking at the confluence:
// a sideways "Y" right of the copy on landscape screens, an upright one between the name and the copy on portrait.
//
// The particle function is GLSL (see gl.js for the Pt struct, hash and uniforms); every particle is derived from its
// id and the time, so there are no buffers. Ink indices: 0 love, 1 rose, 2 foam, 3 pine, 4 iris, 5 subtle.
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
Pt particle(uint id,vec4 h,float t,float it){
  Pt o;
  float f=float(id)/uN;
  if(f<.8){
    float k=float(id&1u);
    float sp=1.2+1.1*h.y;
    float z=ZT-mod(h.x*ZL+sp*t,ZL);
    float w,S;
    vec3 c=ctr(z,k,w,S);
    float halo=step(.78,fract(h.z*7.31));
    float rr=w*sqrt(-log(1.-.96*h.z))*.5*(1.+1.5*halo);
    float ph=6.2832*h.w+1.7*z*(1.-.65*S);
    o.p=c+vec3(cos(ph),sin(ph),0.)*rr;
    vec3 base=k<.5?mix(uInk[0],uInk[1],h.y*h.y*.8):mix(uInk[2],uInk[3],h.y*.9);
    float m=smoothstep(5.,-2.5,z)*(h.y<.22?.4:.92);
    o.c=mix(base,uInk[4],m);
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
}`;

const T = 3.4;
// Camera keys, landscape (L) and portrait (P), with the same times. The camera faces upstream the whole time, so
// the reveal needs no turn. ap/blur: depth of field (aperture and maximum blur, in CSS px); exp: exposure;
// shift: lens shift in NDC units.
const L = [
  { t: 0, pos: [15.5, 10.2, -24.5], tgt: [0, 0, -0.5], roll: 0, fov: 40, focus: 31, ap: 1.4, blur: 16, exp: 0.62, shift: [0.2, 0.03] },
  { t: 0.26, pos: [16.2, 10.65, -25.5], tgt: [0, 0, -0.5], roll: -0.015, fov: 39.5, focus: 32, ap: 1.4, blur: 16, exp: 0.78, shift: [0.2, 0.03] },
  { t: 1.0, pos: [6.6, 4.1, -9.2], tgt: [-0.5, 0, 1.6], roll: 0.08, fov: 44, focus: 11, ap: 1, blur: 16, exp: 1, shift: [0.08, 0] },
  { t: 1.5, pos: [0.9, 0.75, -1.3], tgt: [-1.0, -0.3, 8], roll: 0.2, fov: 52, focus: 4, ap: 0.8, blur: 16, exp: 1.1, shift: [0, 0] },
  { t: 1.92, pos: [-0.5, 1.1, 3.4], tgt: [0.2, 0.2, 16], roll: 0.22, fov: 54, focus: 8, ap: 1.2, blur: 18, exp: 1.04, shift: [0.04, 0] },
  { t: 2.55, pos: [3.9, 3.7, -6.9], tgt: [0.2, 0, 0.5], roll: 0.08, fov: 42, focus: 11, ap: 3, blur: 22, exp: 1, shift: [0.18, 0.02] },
  { t: 3.04, pos: [7.75, 5.25, -11.75], tgt: [0.02, 0, -0.45], roll: 0.01, fov: 39.5, focus: 13.5, ap: 4.2, blur: 26, exp: 1, shift: [0.26, 0.03] },
  { t: 3.4, pos: [7.4, 5.0, -11.3], tgt: [0, 0, -0.5], roll: 0, fov: 40, focus: 13.5, ap: 4.2, blur: 26, exp: 1, shift: [0.26, 0.03] },
];
const P = [
  { t: 0, pos: [1.1, 7.2, -30.5], tgt: [0, 0.5, 4], roll: 0, fov: 56, focus: 31, ap: 1.4, blur: 16, exp: 0.62, shift: [0, 0] },
  { t: 0.26, pos: [1.15, 7.5, -31.8], tgt: [0, 0.5, 4], roll: -0.015, fov: 55.5, focus: 32, ap: 1.4, blur: 16, exp: 0.78, shift: [0, 0] },
  { t: 1.0, pos: [0.7, 3.2, -11.5], tgt: [-0.2, 0.2, 5], roll: 0.07, fov: 60, focus: 11, ap: 1, blur: 16, exp: 1, shift: [0, 0] },
  { t: 1.5, pos: [-0.7, 0.8, -1.0], tgt: [-0.4, 0.2, 12], roll: 0.16, fov: 64, focus: 4, ap: 0.8, blur: 16, exp: 1.1, shift: [0, 0] },
  { t: 1.92, pos: [-0.5, 1.3, 3.6], tgt: [0.1, 0.4, 16], roll: 0.18, fov: 64, focus: 7, ap: 1.2, blur: 18, exp: 1.04, shift: [0, 0] },
  { t: 2.55, pos: [0.4, 2.9, -7.4], tgt: [0.1, 0.45, 4.5], roll: 0.06, fov: 58, focus: 11, ap: 3, blur: 22, exp: 1, shift: [0, 0] },
  { t: 3.04, pos: [0.52, 3.6, -12.6], tgt: [0, 0.5, 3.9], roll: 0.01, fov: 57.5, focus: 13, ap: 4, blur: 24, exp: 1, shift: [0, 0] },
  { t: 3.4, pos: [0.5, 3.5, -12.2], tgt: [0, 0.5, 4], roll: 0, fov: 58, focus: 13, ap: 4, blur: 24, exp: 1, shift: [0, 0] },
];

// A slow drift once the intro has settled (it fades in over 2.2 s after the end), along the camera's own axes.
function idleDrift(pose, it, ft) {
  const k = smooth(T, T + 2.2, it);
  if (k > 0) rig(pose, Math.sin(ft * 0.13) * 0.32 * k, Math.sin(ft * 0.09 + 1.2) * 0.16 * k, Math.sin(ft * 0.071) * 0.22 * k, 0.15);
  return pose;
}

export function createV1() {
  let path = makePath(L);
  return {
    N: 26000,
    T,
    glsl: GLSL,
    gain: { dark: 0.95, light: 0.62 },
    trail: { time: 0.3, width: 0.75, alpha: { dark: 0.5, light: 0.45 } },
    vignette: { dark: 0.55, light: 0.3 },
    // portrait: 0 (landscape) .. 1 (portrait), from the stage's aspect ratio
    layout(portrait) {
      path = makePath(portrait <= 0 ? L : portrait >= 1 ? P : blendKeys(L, P, portrait));
    },
    // Depth fog [start, density, near fade from, near fade to]; the near fade widens while the camera is inside the
    // knot (around 1.65 s), so the membrane does not fill the screen.
    fog(it) {
      const k = Math.exp(-(((it - 1.65) / 0.4) ** 2));
      return [9, 0.042, 0.9 + 0.5 * k, 2.6 + 1.0 * k];
    },
    // Soft glows behind the knot and the two arms: world point, radius (share of the height), strength, ink.
    glows: [
      { p: [0, 0, 0], r: 0.2, a: { dark: 0.18, light: 0.12 }, ink: 4 },
      { p: [4.5, 0.5, 16], r: 0.32, a: { dark: 0.05, light: 0.035 }, ink: 0 },
      { p: [-4.5, -0.5, 16], r: 0.32, a: { dark: 0.05, light: 0.035 }, ink: 2 },
    ],
    // The name's intro motion for k = 1 (start) .. 0 (rest): a lift (em) and a scale, transform only.
    nameMotion: (k) => ({ y: 0.05 * k, s: 1 + 0.07 * k }),
    // The camera at intro time it and flow time ft; ptr in -1..1; scroll in viewport heights (>= 0).
    pose(out, it, ft, ptr, scroll) {
      path(it, out);
      rig(out, ptr[0] * 0.6, ptr[1] * 0.32, 0, 0.18);
      idleDrift(out, it, ft);
      // Scrolling past the landing, the camera keeps travelling toward the knot.
      const q = Math.min(Math.max(scroll, 0), 1.2);
      if (q > 0) rig(out, -0.4 * q, 0.5 * q, 2.6 * q, 0.85);
      return out;
    },
  };
}
