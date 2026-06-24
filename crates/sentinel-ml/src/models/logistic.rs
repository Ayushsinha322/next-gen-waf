//! Logistic regression — a small, dependency-free trainable linear classifier.
//!
//! This is a *genuinely trained* model: weights are learned from a labeled
//! corpus by batch gradient descent with L2 regularisation, not hand-tuned.
//! Training is deterministic (zero-initialised weights, full-batch updates),
//! so a given corpus always yields the same model — important for
//! reproducible validation numbers.
//!
//! Inference is a dot product plus a sigmoid: O(d) per request, where `d` is
//! the feature dimension (24). Negligible on the hot path.

use serde::{Deserialize, Serialize};

/// A trained logistic-regression classifier: `p = σ(w·x + b)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogisticRegression {
    /// Learned feature weights (length = feature dimension).
    pub weights: Vec<f32>,
    /// Learned bias / intercept.
    pub bias: f32,
}

/// Hyper-parameters for [`LogisticRegression::fit`].
#[derive(Debug, Clone, Copy)]
pub struct TrainConfig {
    /// Number of full-batch gradient-descent passes.
    pub epochs: usize,
    /// Learning rate.
    pub lr: f32,
    /// L2 (ridge) regularisation strength — penalises large weights to curb
    /// overfitting on the bundled corpus.
    pub l2: f32,
}

impl Default for TrainConfig {
    fn default() -> Self {
        Self {
            epochs: 800,
            lr: 0.6,
            l2: 1e-3,
        }
    }
}

#[inline]
fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

#[inline]
fn dot(w: &[f32], x: &[f32]) -> f32 {
    w.iter().zip(x).map(|(a, b)| a * b).sum()
}

impl LogisticRegression {
    /// Train a classifier on `x` (rows of feature vectors) labelled by `y`
    /// (1.0 = attack, 0.0 = benign).  Deterministic for a fixed input.
    ///
    /// Returns a zero model if the input is empty or ragged.
    pub fn fit(x: &[Vec<f32>], y: &[f32], cfg: TrainConfig) -> Self {
        let n = x.len();
        if n == 0 || x.len() != y.len() {
            return Self {
                weights: Vec::new(),
                bias: 0.0,
            };
        }
        let d = x[0].len();
        if x.iter().any(|row| row.len() != d) {
            return Self {
                weights: vec![0.0; d],
                bias: 0.0,
            };
        }

        let mut w = vec![0.0f32; d];
        let mut b = 0.0f32;
        let inv_n = 1.0 / n as f32;

        for _ in 0..cfg.epochs {
            let mut grad_w = vec![0.0f32; d];
            let mut grad_b = 0.0f32;

            for (xi, &yi) in x.iter().zip(y.iter()) {
                let p = sigmoid(dot(&w, xi) + b);
                let err = p - yi; // dL/dz for binary cross-entropy
                for j in 0..d {
                    grad_w[j] += err * xi[j];
                }
                grad_b += err;
            }

            // Gradient step with L2 on weights (not on bias).
            for j in 0..d {
                w[j] -= cfg.lr * (grad_w[j] * inv_n + cfg.l2 * w[j]);
            }
            b -= cfg.lr * grad_b * inv_n;
        }

        Self { weights: w, bias: b }
    }

    /// Predicted attack probability ∈ [0, 1] for one feature vector.
    pub fn predict_proba(&self, x: &[f32]) -> f32 {
        if self.weights.len() != x.len() {
            return 0.0;
        }
        sigmoid(dot(&self.weights, x) + self.bias)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A linearly separable toy problem: y = 1 iff feature[0] > 0.5.
    #[test]
    fn learns_linearly_separable() {
        let mut x = Vec::new();
        let mut y = Vec::new();
        for i in 0..100 {
            let f = i as f32 / 100.0;
            x.push(vec![f, 0.3]);
            y.push(if f > 0.5 { 1.0 } else { 0.0 });
        }
        let model = LogisticRegression::fit(&x, &y, TrainConfig::default());

        assert!(model.predict_proba(&[0.9, 0.3]) > 0.8, "high feature → attack");
        assert!(model.predict_proba(&[0.1, 0.3]) < 0.2, "low feature → benign");
        // The discriminative feature must carry more weight than the noise one.
        assert!(model.weights[0].abs() > model.weights[1].abs());
    }

    #[test]
    fn empty_input_is_safe() {
        let model = LogisticRegression::fit(&[], &[], TrainConfig::default());
        assert_eq!(model.predict_proba(&[0.1, 0.2]), 0.0);
    }

    #[test]
    fn deterministic_training() {
        let x = vec![vec![0.1, 0.9], vec![0.8, 0.2], vec![0.6, 0.6]];
        let y = vec![0.0, 1.0, 1.0];
        let m1 = LogisticRegression::fit(&x, &y, TrainConfig::default());
        let m2 = LogisticRegression::fit(&x, &y, TrainConfig::default());
        assert_eq!(m1.weights, m2.weights);
        assert_eq!(m1.bias, m2.bias);
    }
}
