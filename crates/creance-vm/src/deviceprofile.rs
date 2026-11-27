//! Device profile derivation (B-class L1): the browser-visible hardware
//! answers — WebGL vendor/renderer, hardwareConcurrency, deviceMemory,
//! screen — derived deterministically from the persona identity so one
//! persona always answers as ONE plausible consumer machine. Derivation
//! material is the guest username (itself seed-derived): no seed handling
//! needed here, and the profile is stable across rebuilds exactly when
//! the identity is.

/// The browser-visible device persona.
#[derive(Clone, Debug, PartialEq)]
pub struct DeviceProfile {
    /// UNMASKED_VENDOR_WEBGL answer.
    pub gpu_vendor: String,
    /// UNMASKED_RENDERER_WEBGL answer — a real consumer GPU string,
    /// ANGLE-flavoured as a genuine Chrome-on-Windows/Linux answer.
    pub gpu_renderer: String,
    pub hardware_concurrency: u32,
    pub device_memory: u32,
    pub screen_width: u32,
    pub screen_height: u32,
}

/// Real consumer GPU answers as Chrome reports them under ANGLE. Mixed
/// Intel/AMD/NVIDIA mobile parts — an OEM-matched pairing would be even
/// better, but any of these is a plausible laptop answer; llvmpipe and
/// SwiftShader (the VM defaults) never are.
const GPUS: &[(&str, &str)] = &[
    (
        "Google Inc. (Intel)",
        "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    ),
    (
        "Google Inc. (Intel)",
        "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
    ),
    (
        "Google Inc. (AMD)",
        "ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
    ),
    (
        "Google Inc. (Intel)",
        "ANGLE (Intel, Mesa Intel(R) UHD Graphics (CML GT2), OpenGL 4.6)",
    ),
    (
        "Google Inc. (NVIDIA)",
        "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    ),
];

const SCREENS: &[(u32, u32)] = &[(1920, 1080), (1920, 1080), (1366, 768), (2560, 1440)];

impl DeviceProfile {
    /// Derives the device persona from identity material (the guest
    /// username — itself seed-stable). Same material → same machine.
    pub fn derive(identity_material: &str) -> DeviceProfile {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(b"creance-device-v1\x00");
        h.update(identity_material.as_bytes());
        let d: [u8; 32] = h.finalize().into();
        let (vendor, renderer) = GPUS[(d[0] as usize) % GPUS.len()];
        let (sw, sh) = SCREENS[(d[1] as usize) % SCREENS.len()];
        DeviceProfile {
            gpu_vendor: vendor.to_owned(),
            gpu_renderer: renderer.to_owned(),
            hardware_concurrency: [4u32, 8, 8, 12, 16][(d[2] as usize) % 5],
            device_memory: [4u32, 8, 8, 16][(d[3] as usize) % 4],
            screen_width: sw,
            screen_height: sh,
        }
    }

    /// The JSON the injection script carries — values only, no logic.
    pub fn json(&self) -> String {
        serde_json::json!({
            "gpuVendor": self.gpu_vendor,
            "gpuRenderer": self.gpu_renderer,
            "hardwareConcurrency": self.hardware_concurrency,
            "deviceMemory": self.device_memory,
            "screenWidth": self.screen_width,
            "screenHeight": self.screen_height,
        })
        .to_string()
    }
}

/// The fingerprint-injection content script (B-class L1, path-c honest
/// scope): runs in the MAIN world at document_start and re-answers the
/// VM-telling browser surface — WebGL vendor/renderer, hardwareConcurrency,
/// deviceMemory. Honest boundary: JS-layer hooks are detectable by
/// top-tier deep inspection (toString races, ordering probes) — this
/// covers shallow-to-mid fingerprinting, and that is the documented
/// promise. `__DEVICEJSON__` is replaced at provision-render time.
pub const INJECT_JS: &str = r#"(function () {
  'use strict';
  var P = __DEVICEJSON__;
  function nativeish(fn) {
    try {
      fn.toString = function () { return 'function getParameter() { [native code] }'; };
    } catch (e) {}
    return fn;
  }
  function patchGL(proto) {
    if (!proto) return;
    var orig = proto.getParameter;
    if (typeof orig !== 'function') return;
    proto.getParameter = nativeish(function (param) {
      if (param === 37445) return P.gpuVendor;
      if (param === 37446) return P.gpuRenderer;
      return orig.call(this, param);
    });
  }
  try { patchGL(window.WebGLRenderingContext && window.WebGLRenderingContext.prototype); } catch (e) {}
  try { patchGL(window.WebGL2RenderingContext && window.WebGL2RenderingContext.prototype); } catch (e) {}
  function def(obj, key, value) {
    try { Object.defineProperty(obj, key, { get: function () { return value; }, configurable: true }); } catch (e) {}
  }
  def(navigator, 'hardwareConcurrency', P.hardwareConcurrency);
  def(navigator, 'deviceMemory', P.deviceMemory);
  def(screen, 'width', P.screenWidth);
  def(screen, 'height', P.screenHeight);
  def(screen, 'availWidth', P.screenWidth);
  def(screen, 'availHeight', P.screenHeight - 40);
})();
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_plausible() {
        let a = DeviceProfile::derive("devbda37e6c");
        let b = DeviceProfile::derive("devbda37e6c");
        assert_eq!(a, b);
        assert_ne!(a.gpu_renderer, "");
        // never the VM tells
        assert!(!a.gpu_renderer.contains("llvmpipe"));
        assert!(!a.gpu_renderer.contains("SwiftShader"));
        assert!(a.hardware_concurrency >= 4);
        // distinct identities can differ (not guaranteed per-pair, but the
        // pool must actually vary across a sample)
        let mut renderers = std::collections::HashSet::new();
        for i in 0..20 {
            renderers.insert(DeviceProfile::derive(&format!("dev{i:08x}")).gpu_renderer);
        }
        assert!(renderers.len() > 1, "derivation must spread over the pool");
    }
}
