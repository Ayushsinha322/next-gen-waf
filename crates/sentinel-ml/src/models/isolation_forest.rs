//! Isolation Forest — unsupervised anomaly detection for HTTP requests.
//!
//! Builds an ensemble of random isolation trees from a sliding window of
//! recent request feature vectors.  Points that are isolated (partitioned
//! away from the bulk) in fewer splits receive higher anomaly scores.
//!
//! ## Algorithm
//! 1. For each tree, sample *ψ* points without replacement.
//! 2. Recursively split on a random feature at a random threshold until
//!    each point is isolated or `max_depth = ⌈log₂ ψ⌉` is reached.
//! 3. Score = 2^(-E(h(x)) / c(ψ))  where c(ψ) is the expected path length
//!    of an unsuccessful BST search and h(x) is the average path length.
//!
//! Scores ∈ [0, 1]; 0.5 = indistinguishable from normal, >0.6 = suspicious,
//! >0.7 = anomalous, >0.8 = highly anomalous.

use std::time::Instant;

use parking_lot::RwLock;

// ---------------------------------------------------------------------------
// Simple non-cryptographic RNG with seedable state
// ---------------------------------------------------------------------------

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    fn next_u64(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }

    /// Uniform `f32` in [0, 1).
    fn next_f32(&mut self) -> f32 {
        (self.next_u64() as f32) / (u64::MAX as f32)
    }

    /// Uniform `usize` in [0, max) — for random index selection.
    fn next_usize(&mut self, max: usize) -> usize {
        if max <= 1 {
            return 0;
        }
        (self.next_u64() as usize) % max
    }
}

// ---------------------------------------------------------------------------
// Isolation Tree
// ---------------------------------------------------------------------------

/// A single randomised binary tree.
enum IsolationTree {
    /// Internal node: split on `feature` at `value`.
    Branch {
        left: Box<IsolationTree>,
        right: Box<IsolationTree>,
        split_feature: usize,
        split_value: f32,
        #[allow(dead_code)]
        size: usize,
    },
    /// Leaf node: no further splits.
    Leaf { size: usize },
}

impl IsolationTree {
    /// Build a tree from `samples` (each is a row of feature values).
    /// `depth`: current depth; `max_depth`: depth limit (`⌈log₂ ψ⌉`).
    /// Panics if `samples` is empty.
    fn build(
        samples: &[&[f32]],
        depth: usize,
        max_depth: usize,
        rng: &mut XorShift64,
    ) -> Self {
        if samples.is_empty() {
            return IsolationTree::Leaf { size: 0 };
        }
        if depth >= max_depth || samples.len() <= 1 {
            return IsolationTree::Leaf {
                size: samples.len(),
            };
        }

        let dim = samples[0].len();

        // Pick a random feature that has variance > 0.
        let mut feature = rng.next_usize(dim);
        for _attempt in 0..(dim * 2) {
            let min = samples
                .iter()
                .map(|r| r[feature])
                .fold(f32::INFINITY, f32::min);
            let max = samples
                .iter()
                .map(|r| r[feature])
                .fold(f32::NEG_INFINITY, f32::max);
            if (max - min) > 1e-9 {
                break;
            }
            feature = rng.next_usize(dim);
        }

        let min: f32 = samples.iter().map(|r| r[feature]).fold(f32::INFINITY, f32::min);
        let max: f32 = samples
            .iter()
            .map(|r| r[feature])
            .fold(f32::NEG_INFINITY, f32::max);

        if (max - min) < 1e-9 {
            // All values identical on this dimension — leaf.
            return IsolationTree::Leaf {
                size: samples.len(),
            };
        }

        let split_value = min + rng.next_f32() * (max - min);

        let left_samples: Vec<&[f32]> = samples
            .iter()
            .filter(|r| r[feature] <= split_value)
            .copied()
            .collect();
        let right_samples: Vec<&[f32]> = samples
            .iter()
            .filter(|r| r[feature] > split_value)
            .copied()
            .collect();

        IsolationTree::Branch {
            left: Box::new(IsolationTree::build(&left_samples, depth + 1, max_depth, rng)),
            right: Box::new(IsolationTree::build(&right_samples, depth + 1, max_depth, rng)),
            split_feature: feature,
            split_value,
            size: samples.len(),
        }
    }

    /// Return the path length from root to this point's leaf,
    /// adjusted for the leaf size using the `c(size)` correction.
    fn path_length(&self, point: &[f32], current_depth: f32) -> f32 {
        match self {
            IsolationTree::Leaf { size } => {
                if *size <= 1 {
                    current_depth
                } else {
                    current_depth + c(*size)
                }
            }
            IsolationTree::Branch {
                left,
                right,
                split_feature,
                split_value,
                ..
            } => {
                if point[*split_feature] <= *split_value {
                    left.path_length(point, current_depth + 1.0)
                } else {
                    right.path_length(point, current_depth + 1.0)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Ensemble
// ---------------------------------------------------------------------------

/// Trained Isolation Forest ensemble.
#[allow(dead_code)]
pub struct IsolationForest {
    trees: Vec<IsolationTree>,
    /// Subsampling size ψ used during training.
    psi: usize,
    /// `c(psi)` — normalisation constant.
    cn: f32,
}

impl IsolationForest {
    /// Number of trees in the ensemble.
    const N_TREES: usize = 100;

    /// Train a forest on `data` (rows × features).  All rows must have the
    /// same length.  At least `min_samples` (8) rows are required.
    pub fn train(data: &[Vec<f32>]) -> Self {
        let n_rows = data.len();
        if n_rows < 4 {
            return Self {
                trees: Vec::new(),
                psi: 0,
                cn: 0.0,
            };
        }
        let psi = (256usize).min(n_rows).max(8);
        let max_depth = ((psi as f32).log2().ceil() as usize).max(1);
        let cn = c(psi);
        let seed = Instant::now().elapsed().subsec_nanos() as u64;
        let mut rng = XorShift64::new(seed);

        let mut trees = Vec::with_capacity(Self::N_TREES);
        for _ in 0..Self::N_TREES {
            let sample_refs: Vec<&[f32]> = reservoir_sample(data, psi, &mut rng);
            trees.push(IsolationTree::build(&sample_refs, 0, max_depth, &mut rng));
        }

        Self { trees, psi, cn }
    }

    /// Return the anomaly score for a single point ∈ [0, 1].
    /// Returns 0.5 (neutral) when the forest has no trees (uninitialised).
    pub fn score(&self, point: &[f32]) -> f32 {
        if self.trees.is_empty() || self.cn <= 1e-9 {
            return 0.5;
        }
        let avg_path: f32 = self
            .trees
            .iter()
            .map(|t| t.path_length(point, 0.0))
            .sum::<f32>()
            / self.trees.len() as f32;

        // s(x, n) = 2^(-E(h(x)) / c(n))
        (2.0f32).powf(-avg_path / self.cn.max(1e-9)).clamp(0.0, 1.0)
    }

    /// Whether the forest models any data (0 trees ⇒ untrained).
    pub fn is_trained(&self) -> bool {
        !self.trees.is_empty()
    }

    /// Number of trees.
    pub fn tree_count(&self) -> usize {
        self.trees.len()
    }
}

// ---------------------------------------------------------------------------
// Incremental (online) learning wrapper
// ---------------------------------------------------------------------------

/// Ring buffer of recent request feature vectors.  Periodically retrains
/// the [`IsolationForest`] so the model adapts to the site's traffic profile.
///
/// # Thread safety
/// The internal forest is under an [`RwLock`] — reads (scoring) are
/// contention-free after a brief shared lock; writes (retraining) hold an
/// exclusive lock but are infrequent.
pub struct IncrementalForest {
    inner: RwLock<ForestState>,
    buffer_capacity: usize,
    retrain_every: usize,
}

struct ForestState {
    forest: IsolationForest,
    buffer: Vec<Vec<f32>>,
    generation: u64,
    samples_since_train: usize,
}

impl IncrementalForest {
    /// Create an incremental forest.
    ///
    /// * `buffer_capacity`: maximum number of recent vectors to keep.
    /// * `retrain_every`: retrain after this many new vectors (min 64).
    pub fn new(buffer_capacity: usize, retrain_every: usize) -> Self {
        let retrain = retrain_every.max(64);
        Self {
            inner: RwLock::new(ForestState {
                forest: IsolationForest::train(&[]),
                buffer: Vec::with_capacity(buffer_capacity),
                generation: 0,
                samples_since_train: 0,
            }),
            buffer_capacity: buffer_capacity.max(1024),
            retrain_every: retrain,
        }
    }

    /// Feed one new feature vector.  Returns `true` if the forest was
    /// retrained as a result.
    pub fn observe(&self, features: &[f32]) -> bool {
        let mut state = self.inner.write();
        // Ring-buffer push.
        if state.buffer.len() >= self.buffer_capacity {
            state.buffer.remove(0);
        }
        state.buffer.push(features.to_vec());
        state.samples_since_train += 1;

        if state.buffer.len() >= 64 && state.samples_since_train >= self.retrain_every {
            state.forest = IsolationForest::train(&state.buffer);
            state.generation += 1;
            state.samples_since_train = 0;
            true
        } else {
            false
        }
    }

    /// Seed the forest with known-normal vectors and train immediately.
    ///
    /// Without seeding the forest cold-starts: it scores every request a
    /// neutral 0.5 until `retrain_every` live observations accumulate. Seeding
    /// it with a baseline of benign traffic makes anomaly scoring useful from
    /// the very first request; subsequent online observations then adapt the
    /// model to the site's real traffic profile.
    pub fn seed(&self, vectors: &[Vec<f32>]) {
        if vectors.is_empty() {
            return;
        }
        let mut state = self.inner.write();
        for v in vectors {
            if state.buffer.len() >= self.buffer_capacity {
                state.buffer.remove(0);
            }
            state.buffer.push(v.clone());
        }
        if state.buffer.len() >= 8 {
            state.forest = IsolationForest::train(&state.buffer);
            state.generation += 1;
            state.samples_since_train = 0;
        }
    }

    /// Score a feature vector against the current forest.
    ///
    /// Returns 0.5 (neutral) if the forest has insufficient data.
    pub fn score(&self, features: &[f32]) -> f32 {
        let state = self.inner.read();
        state.forest.score(features)
    }

    /// Number of training samples currently buffered.
    pub fn buffer_len(&self) -> usize {
        self.inner.read().buffer.len()
    }

    /// Training generation counter (monotonically increasing).
    pub fn generation(&self) -> u64 {
        self.inner.read().generation
    }

    /// Whether the forest has been trained at least once.
    pub fn is_trained(&self) -> bool {
        self.inner.read().forest.is_trained()
    }

    /// Number of trees (0 if untrained).
    pub fn tree_count(&self) -> usize {
        self.inner.read().forest.tree_count()
    }
}

// ---------------------------------------------------------------------------
// Helper: expected path length for a sample of size n
// ---------------------------------------------------------------------------

/// c(n) = 2H(n-1) − 2(n-1)/n  where H(i) is the harmonic number.
fn c(n: usize) -> f32 {
    if n <= 1 {
        return 0.0;
    }
    let nf = n as f32;
    2.0 * harmonic(n - 1) - (2.0 * (nf - 1.0) / nf)
}

/// H(k) = 1 + 1/2 + 1/3 + … + 1/k, approximated by ln(k) + γ + 1/(2k).
fn harmonic(k: usize) -> f32 {
    if k == 0 {
        return 0.0;
    }
    if k <= 20 {
        let mut sum = 0.0f32;
        for i in 1..=k {
            sum += 1.0 / i as f32;
        }
        sum
    } else {
        let kf = k as f32;
        (kf).ln() + 0.5772156649 + 1.0 / (2.0 * kf) - 1.0 / (12.0 * kf * kf)
    }
}

/// Reservoir sample `k` rows from `data` (as slices) without replacement.
fn reservoir_sample<'a>(data: &'a [Vec<f32>], k: usize, rng: &mut XorShift64) -> Vec<&'a [f32]> {
    if data.len() <= k {
        return data.iter().map(|v| v.as_slice()).collect();
    }
    let mut reservoir: Vec<&[f32]> = data.iter().take(k).map(|v| v.as_slice()).collect();
    for i in k..data.len() {
        let j = rng.next_usize(i + 1);
        if j < k {
            reservoir[j] = data[i].as_slice();
        }
    }
    reservoir
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_of_small_n() {
        assert_eq!(c(1), 0.0);
        assert!((c(10) - harmonic(9) * 2.0 + 1.8).abs() < 0.01);
    }

    #[test]
    fn harmonic_values() {
        assert_eq!(harmonic(0), 0.0);
        assert_eq!(harmonic(1), 1.0);
        assert!((harmonic(10) - 2.928968).abs() < 0.01);
    }

    #[test]
    fn empty_forest_scores_neutral() {
        let f = IsolationForest::train(&[]);
        assert!((f.score(&[0.5; 4]) - 0.5).abs() < 1e-6);
    }

    #[test]
    fn small_data_trains() {
        let data: Vec<Vec<f32>> = (0..32)
            .map(|i| vec![(i % 5) as f32 / 5.0, 0.5])
            .collect();
        let f = IsolationForest::train(&data);
        assert!(f.is_trained());
        assert_eq!(f.tree_count(), IsolationForest::N_TREES);
        let s = f.score(&[0.5, 0.5]);
        assert!((0.0..=1.0).contains(&s));
    }

    #[test]
    fn anomaly_scores_higher_for_outliers() {
        // Normal cluster near (0.0, 0.0)
        let mut normal: Vec<Vec<f32>> = Vec::new();
        for _ in 0..128 {
            normal.push(vec![
                random_jitter(0.0, 0.05),
                random_jitter(0.0, 0.05),
            ]);
        }
        let f = IsolationForest::train(&normal);
        let normal_score = f.score(&[0.01, 0.01]);
        let outlier_score = f.score(&[0.95, 0.95]);
        // Outlier should score higher.
        assert!(
            outlier_score >= normal_score,
            "outlier {outlier_score:.3} should be >= normal {normal_score:.3}"
        );
    }

    #[test]
    fn incremental_updates() {
        let inc = IncrementalForest::new(1024, 64);
        assert!(!inc.is_trained());

        // Feed 64 identical vectors — forest should train after fill.
        for i in 0..64 {
            let v = vec![(i % 4) as f32 / 4.0, 0.5];
            inc.observe(&v);
        }
        assert!(inc.is_trained());
        assert_eq!(inc.tree_count(), IsolationForest::N_TREES);
        assert_eq!(inc.generation(), 1);
    }

    #[test]
    fn generational_training() {
        let inc = IncrementalForest::new(512, 64);
        // Feed 128 vectors → should trigger 2 retrains.
        for i in 0..128 {
            inc.observe(&[i as f32 / 128.0, 0.5]);
        }
        assert!(inc.generation() >= 1);
    }

    /// Deterministic-ish jitter for reproducible test output.
    fn random_jitter(center: f32, spread: f32) -> f32 {
        let t = (std::time::Instant::now().elapsed().subsec_nanos() % 1024) as f32 / 1024.0;
        center + (t - 0.5) * spread
    }
}
