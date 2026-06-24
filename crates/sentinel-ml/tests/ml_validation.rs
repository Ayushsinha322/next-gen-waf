//! Detection-accuracy validation for the trained payload classifier.
//!
//! Trains on one split of the bundled labeled corpus and measures
//! precision / recall / FPR / FNR / F1 on a held-out split it never saw.
//! This produces the real accuracy numbers a commercial WAF must publish —
//! run with `--nocapture` to see the confusion matrix and metrics.

use sentinel_ml::features::FeatureVector;
use sentinel_ml::models::corpus::training_corpus;
use sentinel_ml::models::payload_classifier::PayloadClassifier;

struct Metrics {
    tp: usize,
    tn: usize,
    fp: usize,
    fn_: usize,
}

impl Metrics {
    fn precision(&self) -> f32 {
        if self.tp + self.fp == 0 {
            return 1.0;
        }
        self.tp as f32 / (self.tp + self.fp) as f32
    }
    fn recall(&self) -> f32 {
        if self.tp + self.fn_ == 0 {
            return 1.0;
        }
        self.tp as f32 / (self.tp + self.fn_) as f32
    }
    /// False-positive rate: benign requests wrongly flagged.
    fn fpr(&self) -> f32 {
        if self.fp + self.tn == 0 {
            return 0.0;
        }
        self.fp as f32 / (self.fp + self.tn) as f32
    }
    /// False-negative rate: attacks missed.
    fn fnr(&self) -> f32 {
        if self.fn_ + self.tp == 0 {
            return 0.0;
        }
        self.fn_ as f32 / (self.fn_ + self.tp) as f32
    }
    fn f1(&self) -> f32 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            return 0.0;
        }
        2.0 * p * r / (p + r)
    }
    fn accuracy(&self) -> f32 {
        let total = self.tp + self.tn + self.fp + self.fn_;
        if total == 0 {
            return 0.0;
        }
        (self.tp + self.tn) as f32 / total as f32
    }
}

/// Deterministic train/test split: every 4th sample (by index) is held out for
/// testing, the rest train. ~75/25 split, reproducible.
fn split() -> (Vec<Vec<f32>>, Vec<f32>, Vec<(FeatureVector, f32)>) {
    let corpus = training_corpus();
    let mut train_x = Vec::new();
    let mut train_y = Vec::new();
    let mut test = Vec::new();
    for (i, s) in corpus.into_iter().enumerate() {
        if i % 4 == 3 {
            test.push((s.fv, s.label));
        } else {
            train_x.push(s.fv.values.to_vec());
            train_y.push(s.label);
        }
    }
    (train_x, train_y, test)
}

fn evaluate(clf: &PayloadClassifier, test: &[(FeatureVector, f32)], threshold: f32) -> Metrics {
    let (mut tp, mut tn, mut fp, mut fn_) = (0, 0, 0, 0);
    for (fv, label) in test {
        let pred = clf.score(fv) >= threshold;
        let actual = *label >= 0.5;
        match (pred, actual) {
            (true, true) => tp += 1,
            (false, false) => tn += 1,
            (true, false) => fp += 1,
            (false, true) => fn_ += 1,
        }
    }
    Metrics { tp, tn, fp, fn_ }
}

#[test]
fn classifier_meets_accuracy_targets_on_holdout() {
    let (train_x, train_y, test) = split();
    assert!(!test.is_empty(), "held-out set must be non-empty");

    let clf = PayloadClassifier::from_dataset(&train_x, &train_y);
    let m = evaluate(&clf, &test, 0.5);

    println!("\n=== Payload Classifier — held-out validation ===");
    println!("train size: {}   test size: {}", train_x.len(), test.len());
    println!("confusion: TP={} TN={} FP={} FN={}", m.tp, m.tn, m.fp, m.fn_);
    println!("precision : {:.3}", m.precision());
    println!("recall    : {:.3}  (attack detection rate)", m.recall());
    println!("FPR       : {:.3}  (benign wrongly flagged)", m.fpr());
    println!("FNR       : {:.3}  (attacks missed)", m.fnr());
    println!("F1        : {:.3}", m.f1());
    println!("accuracy  : {:.3}\n", m.accuracy());

    // Honest, defensible thresholds for a keyword+structure linear model on
    // this corpus. Tightened to the measured numbers; regressions will trip.
    assert!(m.recall() >= 0.85, "recall {:.3} below 0.85", m.recall());
    assert!(m.fpr() <= 0.15, "FPR {:.3} above 0.15", m.fpr());
    assert!(m.f1() >= 0.85, "F1 {:.3} below 0.85", m.f1());
}

#[test]
fn production_model_separates_attack_from_benign() {
    // The default (production) classifier trained on the full corpus must score
    // obvious attacks well above obvious benign requests.
    let clf = PayloadClassifier::default();

    let attacks = training_corpus()
        .into_iter()
        .filter(|s| s.label == 1.0)
        .map(|s| clf.score(&s.fv))
        .collect::<Vec<_>>();
    let benign = training_corpus()
        .into_iter()
        .filter(|s| s.label == 0.0)
        .map(|s| clf.score(&s.fv))
        .collect::<Vec<_>>();

    let mean = |v: &[f32]| v.iter().sum::<f32>() / v.len() as f32;
    let atk_mean = mean(&attacks);
    let ben_mean = mean(&benign);
    println!("\nmean attack score: {atk_mean:.3}  mean benign score: {ben_mean:.3}");
    assert!(
        atk_mean > ben_mean + 0.3,
        "attack mean {atk_mean:.3} not clearly above benign mean {ben_mean:.3}"
    );
    assert!(atk_mean > 0.6, "attack mean score too low: {atk_mean:.3}");
    assert!(ben_mean < 0.4, "benign mean score too high: {ben_mean:.3}");
}
