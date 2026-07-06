//! External model inference (ONNX Runtime).
//!
//! The ONNX path is gated behind the `ort-inference` feature flag because
//! `ort` v2 downloads the ONNX Runtime shared library at build time, which
//! requires network access and may not be available in all environments.
//!
//! When the feature is enabled:
//!   - `ModelRegistry` loads `.onnx` files from `ml-models/`.
//!   - `OnnxModel::predict(features) → Vec<f32>` runs inference.
//!   - Errors (missing file, shape mismatch) degrade gracefully to a
//!     neutral score of 0.5 rather than crashing the proxy.
//!
//! ## Adding a model
//! 1. Export an ONNX model with input shape `[1, 24]` (float32).
//! 2. Place it in `ml-models/`.
//! 3. Reference it in `WafConfig.ml.models: ["anomaly.onnx"]`.
//! 4. The proxy will load it and call it per request.

use std::collections::HashMap;
use std::path::Path;

use tracing::{info, warn};

use super::features::FEATURE_DIM;

// ---------------------------------------------------------------------------
// ONNX-backed model (feature-gated)
// ---------------------------------------------------------------------------

/// A loaded ONNX model.  Only available with the `ort-inference` feature.
#[cfg(feature = "ort-inference")]
pub struct OnnxModel {
    session: ort::Session,
    input_name: String,
}

#[cfg(feature = "ort-inference")]
impl OnnxModel {
    /// Load an ONNX model from a file path.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let session = ort::Session::builder()?
            .with_model_from_file(path)
            .map_err(|e| anyhow::anyhow!("ONNX load {path:?}: {e}"))?;
        let input_name = session
            .inputs
            .first()
            .map(|i| i.name.clone())
            .unwrap_or_else(|| "input".to_string());
        Ok(Self {
            session,
            input_name,
        })
    }

    /// Run inference on a single feature vector (24 floats).
    /// Returns the raw output tensor as a flat `Vec<f32>`.
    pub fn predict(&self, features: &[f32; FEATURE_DIM]) -> anyhow::Result<Vec<f32>> {
        let array = ndarray::Array2::from_shape_vec((1, FEATURE_DIM), features.to_vec())
            .map_err(|e| anyhow::anyhow!("ONNX input shape: {e}"))?;
        let outputs = self
            .session
            .run(ort::inputs![self.input_name.as_str() => array.view()]?)?;
        let output = outputs
            .first()
            .ok_or_else(|| anyhow::anyhow!("ONNX model produced no output tensors"))?
            .try_extract_tensor::<f32>()
            .map_err(|e| anyhow::anyhow!("ONNX output extract: {e}"))?;
        Ok(output.iter().copied().collect())
    }
}

// ---------------------------------------------------------------------------
// Stub (always compiled when feature is off)
// ---------------------------------------------------------------------------

/// Stub when `ort-inference` is not enabled — always returns neutral.
#[cfg(not(feature = "ort-inference"))]
pub struct OnnxModel;

#[cfg(not(feature = "ort-inference"))]
impl OnnxModel {
    #[allow(unused)]
    pub fn load(_path: &Path) -> anyhow::Result<Self> {
        anyhow::bail!("ONNX inference is not compiled (enable 'ort-inference' feature)")
    }
    #[allow(unused)]
    pub fn predict(&self, _features: &[f32; FEATURE_DIM]) -> anyhow::Result<Vec<f32>> {
        Ok(vec![0.5])
    }
}

// ---------------------------------------------------------------------------
// Model registry
// ---------------------------------------------------------------------------

/// Holds loaded ONNX models keyed by model name (filename stem).
pub struct ModelRegistry {
    models: HashMap<String, OnnxModel>,
}

impl ModelRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            models: HashMap::new(),
        }
    }

    /// Load a model by name.  The path is `ml-models/{name}.onnx`.
    pub fn load(&mut self, name: impl Into<String>, model_dir: &Path) -> anyhow::Result<()> {
        let name = name.into();
        let path = model_dir.join(format!("{name}.onnx"));

        if !path.exists() {
            warn!(path = %path.display(), "ONNX model file not found — model will return neutral scores");
            // Insert a neutral stub so the engine knows about it.
            #[cfg(not(feature = "ort-inference"))]
            {
                self.models.insert(name, OnnxModel);
            }
            return Ok(());
        }

        let model = OnnxModel::load(&path)?;
        info!(name, path = %path.display(), "ONNX model loaded");
        self.models.insert(name, model);
        Ok(())
    }

    /// Run inference on a named model.  Returns `[0.5]` if the model isn't
    /// loaded.
    pub fn predict(&self, name: &str, features: &[f32; FEATURE_DIM]) -> Vec<f32> {
        self.models
            .get(name)
            .and_then(|m| m.predict(features).ok())
            .unwrap_or_else(|| vec![0.5])
    }

    /// Number of loaded models.
    pub fn len(&self) -> usize {
        self.models.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }

    /// Iterator over loaded model names.
    pub fn model_names(&self) -> impl Iterator<Item = &str> {
        self.models.keys().map(|k| k.as_str())
    }
}

impl Default for ModelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_returns_neutral() {
        let reg = ModelRegistry::new();
        let score = reg.predict("nonexistent", &[0.0; FEATURE_DIM]);
        assert_eq!(score, vec![0.5]);
    }

    #[test]
    fn missing_model_file_does_not_panic() {
        let mut reg = ModelRegistry::new();
        let result = reg.load("does_not_exist", Path::new("/nonexistent"));
        // Gracefully continues even if file doesn't exist (warns, stubs).
        assert!(result.is_ok() || reg.is_empty());
    }
}
