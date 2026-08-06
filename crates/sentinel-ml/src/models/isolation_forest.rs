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

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomOrdering};
use std::sync::Arc;

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
    fn build(samples: &[&[f32]], depth: usize, max_depth: usize, rng: &mut XorShift64) -> Self {
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

        let min: f32 = samples
            .iter()
            .map(|r| r[feature])
            .fold(f32::INFINITY, f32::min);
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
            left: Box::new(IsolationTree::build(
                &left_samples,
                depth + 1,
                max_depth,
                rng,
            )),
            right: Box::new(IsolationTree::build(
                &right_samples,
                depth + 1,
                max_depth,
                rng,
            )),
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
/// # Thread safety and hot-path cost
///
/// Scoring is lock-free: the trained forest lives in an [`ArcSwap`], so a scoring
/// request loads a pointer and never blocks — not even while a retrain is running.
/// Observing takes a short mutex to push into a bounded ring buffer, which is O(1).
///
/// This replaces a design that was expensive on the request path in three separate
/// ways, all of them paid by every clean request:
///
///  1. `observe()` took the **write** half of the `RwLock`, so recording a sample
///     blocked all concurrent scoring and serialized observers against each other.
///  2. The ring buffer was a `Vec` evicted with `remove(0)` — an O(n) memmove of
///     the entire buffer (≥1024 feature vectors) on every request once full.
///  3. Retraining ran **inline while still holding that write lock**, so one
///     unlucky request in every `retrain_every` stalled every other request in
///     flight for the duration of a full forest build.
///
/// Now the triggering request still performs the training itself, but it does so
/// after releasing the buffer lock and writes the result with a single atomic
/// pointer swap — so it delays only itself, never other requests.
pub struct IncrementalForest {
    /// Current forest. Read lock-free by `score()`; replaced wholesale on retrain.
    forest: ArcSwap<IsolationForest>,
    /// Recent observations. `VecDeque` so eviction is O(1) rather than O(n).
    buffer: Mutex<VecDeque<Vec<f32>>>,
    generation: AtomicU64,
    samples_since_train: AtomicUsize,
    /// Guards against two requests retraining concurrently; the loser skips.
    retraining: AtomicBool,
    buffer_capacity: usize,
    retrain_every: usize,
}

impl IncrementalForest {
    /// Create an incremental forest.
    ///
    /// * `buffer_capacity`: maximum number of recent vectors to keep.
    /// * `retrain_every`: retrain after this many new vectors (min 64).
    pub fn new(buffer_capacity: usize, retrain_every: usize) -> Self {
        let retrain = retrain_every.max(64);
        let capacity = buffer_capacity.max(1024);
        Self {
            forest: ArcSwap::from_pointee(IsolationForest::train(&[])),
            buffer: Mutex::new(VecDeque::with_capacity(capacity)),
            generation: AtomicU64::new(0),
            samples_since_train: AtomicUsize::new(0),
            retraining: AtomicBool::new(false),
            buffer_capacity: capacity,
            retrain_every: retrain,
        }
    }

    /// Feed one new feature vector. Returns `true` if this call retrained the
    /// forest.
    ///
    /// The buffer lock is held only for the O(1) push; any training happens after
    /// it is released, and publishing the result is a single atomic swap.
    pub fn observe(&self, features: &[f32]) -> bool {
        let snapshot = {
            let mut buf = self.buffer.lock();
            if buf.len() >= self.buffer_capacity {
                buf.pop_front();
            }
            buf.push_back(features.to_vec());

            let seen = self.samples_since_train.fetch_add(1, AtomOrdering::Relaxed) + 1;
            if buf.len() < 64 || seen < self.retrain_every {
                return false;
            }
            // Only one retrain at a time; a concurrent observer just keeps going.
            if self.retraining.swap(true, AtomOrdering::Acquire) {
                return false;
            }
            // Copy out under the lock, then train outside it.
            buf.iter().cloned().collect::<Vec<_>>()
        };

        self.samples_since_train.store(0, AtomOrdering::Relaxed);
        let trained = IsolationForest::train(&snapshot);
        self.forest.store(Arc::new(trained));
        self.generation.fetch_add(1, AtomOrdering::Relaxed);
        self.retraining.store(false, AtomOrdering::Release);
        true
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
        let snapshot = {
            let mut buf = self.buffer.lock();
            for v in vectors {
                if buf.len() >= self.buffer_capacity {
                    buf.pop_front();
                }
                buf.push_back(v.clone());
            }
            if buf.len() < 8 {
                return;
            }
            buf.iter().cloned().collect::<Vec<_>>()
        };

        let trained = IsolationForest::train(&snapshot);
        self.forest.store(Arc::new(trained));
        self.generation.fetch_add(1, AtomOrdering::Relaxed);
        self.samples_since_train.store(0, AtomOrdering::Relaxed);
    }

    /// Score a feature vector against the current forest.
    ///
    /// Lock-free. Returns 0.5 (neutral) if the forest has insufficient data.
    pub fn score(&self, features: &[f32]) -> f32 {
        self.forest.load().score(features)
    }

    /// Number of training samples currently buffered.
    pub fn buffer_len(&self) -> usize {
        self.buffer.lock().len()
    }

    /// Training generation counter (monotonically increasing).
    pub fn generation(&self) -> u64 {
        self.generation.load(AtomOrdering::Relaxed)
    }

    /// Whether the forest has been trained at least once.
    pub fn is_trained(&self) -> bool {
        self.forest.load().is_trained()
    }

    /// Number of trees (0 if untrained).
    pub fn tree_count(&self) -> usize {
        self.forest.load().tree_count()
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
        (kf).ln() + 0.577_215_7 + 1.0 / (2.0 * kf) - 1.0 / (12.0 * kf * kf)
    }
}

/// Reservoir sample `k` rows from `data` (as slices) without replacement.
fn reservoir_sample<'a>(data: &'a [Vec<f32>], k: usize, rng: &mut XorShift64) -> Vec<&'a [f32]> {
    if data.len() <= k {
        return data.iter().map(|v| v.as_slice()).collect();
    }
    let mut reservoir: Vec<&[f32]> = data.iter().take(k).map(|v| v.as_slice()).collect();
    for (i, item) in data.iter().enumerate().skip(k) {
        let j = rng.next_usize(i + 1);
        if j < k {
            reservoir[j] = item.as_slice();
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
        let data: Vec<Vec<f32>> = (0..32).map(|i| vec![(i % 5) as f32 / 5.0, 0.5]).collect();
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
            normal.push(vec![random_jitter(0.0, 0.05), random_jitter(0.0, 0.05)]);
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

    // ── Hot-path cost properties ──────────────────────────────────────────

    #[test]
    fn buffer_stays_bounded_under_sustained_load() {
        // Eviction is O(1) via VecDeque::pop_front; the previous Vec::remove(0)
        // memmoved the whole buffer on every request once full.
        let capacity = 1024; // new() clamps below this
        let inc = IncrementalForest::new(capacity, 64);
        for i in 0..(capacity * 3) {
            inc.observe(&[i as f32 / 100.0, 0.25]);
        }
        assert!(
            inc.buffer_len() <= capacity,
            "buffer grew past capacity: {}",
            inc.buffer_len()
        );
        assert!(inc.generation() >= 1, "never retrained");
    }

    #[test]
    fn scoring_never_blocks_and_stays_valid_during_retraining() {
        // The point of ArcSwap: readers must keep making progress while a retrain
        // is in flight. Under the old RwLock, observe() held the write half and
        // trained inline, so every scorer stalled for the whole forest build.
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc as StdArc;

        let inc = StdArc::new(IncrementalForest::new(2048, 64));
        inc.seed(
            &(0..128)
                .map(|i| vec![i as f32 / 128.0, 0.5])
                .collect::<Vec<_>>(),
        );

        let stop = StdArc::new(AtomicBool::new(false));
        let scores = StdArc::new(AtomicUsize::new(0));

        let readers: Vec<_> = (0..4)
            .map(|_| {
                let inc = StdArc::clone(&inc);
                let stop = StdArc::clone(&stop);
                let scores = StdArc::clone(&scores);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let s = inc.score(&[0.42, 0.5]);
                        assert!(
                            (0.0..=1.0).contains(&s) && !s.is_nan(),
                            "score out of range during retrain: {s}"
                        );
                        scores.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        // Drive many retrains while the readers hammer score().
        let writer = {
            let inc = StdArc::clone(&inc);
            std::thread::spawn(move || {
                for i in 0..2_000 {
                    inc.observe(&[(i % 128) as f32 / 128.0, 0.5]);
                }
            })
        };
        writer.join().expect("writer panicked");
        stop.store(true, Ordering::Relaxed);
        for r in readers {
            r.join().expect("reader panicked");
        }

        assert!(inc.generation() >= 2, "expected several retrains");
        assert!(
            scores.load(Ordering::Relaxed) > 0,
            "readers made no progress — scoring was blocked"
        );
    }

    #[test]
    fn concurrent_observers_do_not_corrupt_state() {
        use std::sync::Arc as StdArc;
        let inc = StdArc::new(IncrementalForest::new(1024, 64));
        let writers: Vec<_> = (0..8)
            .map(|w| {
                let inc = StdArc::clone(&inc);
                std::thread::spawn(move || {
                    for i in 0..500 {
                        inc.observe(&[(w * 500 + i) as f32 / 4000.0, 0.5]);
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().expect("writer panicked");
        }
        assert!(inc.buffer_len() <= 1024);
        assert!(inc.is_trained(), "forest never became trained");
        // A valid score proves the swapped-in forest is intact.
        let s = inc.score(&[0.5, 0.5]);
        assert!((0.0..=1.0).contains(&s) && !s.is_nan(), "invalid score {s}");
    }
}
