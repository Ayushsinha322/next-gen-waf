use std::collections::HashMap;
use std::sync::Arc;

use aho_corasick::AhoCorasick;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use regex::Regex;
use tracing::debug;

// ---------------------------------------------------------------------------
// Pattern registry
// ---------------------------------------------------------------------------

/// A shared, lazily-built registry of compiled patterns.
///
/// Allows multiple `RuleEngine` instances to share compiled `Regex` and
/// `AhoCorasick` automata without redundant compilation.
pub struct PatternRegistry {
    regex_cache: RwLock<HashMap<String, Arc<Regex>>>,
    ac_cache: RwLock<HashMap<String, Arc<AhoCorasick>>>,
}

impl PatternRegistry {
    pub fn new() -> Self {
        Self {
            regex_cache: RwLock::new(HashMap::new()),
            ac_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Get or compile a `Regex`.
    pub fn regex(&self, pattern: &str) -> Result<Arc<Regex>, regex::Error> {
        {
            let cache = self.regex_cache.read();
            if let Some(re) = cache.get(pattern) {
                return Ok(Arc::clone(re));
            }
        }
        let re = Arc::new(Regex::new(pattern)?);
        self.regex_cache
            .write()
            .insert(pattern.to_owned(), Arc::clone(&re));
        debug!(pattern, "compiled new regex");
        Ok(re)
    }

    /// Get or build an Aho-Corasick automaton from a sorted word list.
    pub fn ac_set(&self, words: &[String]) -> anyhow::Result<Arc<AhoCorasick>> {
        let key = words.join("\x00");
        {
            let cache = self.ac_cache.read();
            if let Some(ac) = cache.get(&key) {
                return Ok(Arc::clone(ac));
            }
        }
        let ac = Arc::new(
            aho_corasick::AhoCorasickBuilder::new()
                // ModSecurity @pm / @pmFromFile are case-INSENSITIVE. Matching
                // that (was `false`) recovers scanner-UA, LFI os-file, shell,
                // web-shell, sql-error and other @pmFromFile detections that the
                // rules do not lowercase first.
                .ascii_case_insensitive(true)
                .build(words)
                .map_err(|e| anyhow::anyhow!("AhoCorasick build: {}", e))?,
        );
        self.ac_cache.write().insert(key, Arc::clone(&ac));
        debug!(words = words.len(), "built new AC automaton");
        Ok(ac)
    }

    pub fn regex_count(&self) -> usize {
        self.regex_cache.read().len()
    }

    pub fn ac_count(&self) -> usize {
        self.ac_cache.read().len()
    }
}

impl Default for PatternRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Global pattern registry — avoids recompiling patterns across hot-reloads.
pub static GLOBAL_REGISTRY: Lazy<PatternRegistry> = Lazy::new(PatternRegistry::new);
