use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use tracing::debug;

use crate::dsl::ast::{Operator, RuleFile, RuleItem};

/// Optimization pass: merge adjacent `ContainsWord` operators into a shared
/// Aho-Corasick automaton.
///
/// Currently this is a no-op structural pass — the actual AC sets are built
/// per-rule during emission in `mod.rs`.  Future work: merge identical word
/// lists across rules into a single shared AC set.
pub struct OptimizationHints {
    /// Groups of rule-ids whose ContainsWord lists can share an AC set.
    pub shared_ac_groups: Vec<SharedAcGroup>,
}

pub struct SharedAcGroup {
    pub rule_ids: Vec<u32>,
    pub words: Vec<String>,
}

pub fn optimize(file: &RuleFile) -> OptimizationHints {
    // Collect ContainsWord rules per word-list hash
    let mut groups: std::collections::HashMap<String, Vec<u32>> = std::collections::HashMap::new();

    for item in &file.items {
        if let RuleItem::Rule(rule) = item {
            if let Operator::ContainsWord(words) = &rule.operator {
                let key = words.join("\x00");
                groups.entry(key).or_default().push(rule.id);
            }
        }
    }

    let shared_ac_groups = groups
        .into_iter()
        .filter(|(_, ids)| ids.len() > 1)
        .map(|(key, rule_ids)| SharedAcGroup {
            rule_ids,
            words: key.split('\x00').map(String::from).collect(),
        })
        .collect::<Vec<_>>();

    if !shared_ac_groups.is_empty() {
        debug!(
            groups = shared_ac_groups.len(),
            "optimizer: found shared AC groups"
        );
    }

    OptimizationHints { shared_ac_groups }
}

/// Build an Aho-Corasick automaton from a word list.
pub fn build_ac(words: &[String]) -> anyhow::Result<AhoCorasick> {
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(false)
        .build(words)
        .map_err(|e| anyhow::anyhow!("AhoCorasick build error: {}", e))
}
