//! Built-in ML models — always compiled, no external runtime needed.
//!
//! * [`IsolationForest`](isolation_forest::IsolationForest) —
//!   unsupervised anomaly detection (online-learning via
//!   [`IncrementalForest`](isolation_forest::IncrementalForest)).
//! * [`PayloadClassifier`](payload_classifier::PayloadClassifier) —
//!   multi-category attack-payload scoring (SQLi, XSS, traversal, etc.).

pub mod corpus;
pub mod isolation_forest;
pub mod logistic;
pub mod ngram_classifier;
pub mod payload_classifier;
