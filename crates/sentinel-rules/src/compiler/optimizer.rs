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
///
/// CASE-INSENSITIVE, matching ModSecurity's `@pm` / `@pmFromFile` semantics.
///
/// This was `false`, and the consequence was severe and silent. CRS ships word
/// lists whose entries are written in their natural casing — `Invoke-Expression`,
/// `Add-Computer`, `Net.WebClient` — and matches them against input that rules do
/// NOT lowercase first. With case-sensitive matching, rule 932120's 421-entry
/// PowerShell list was ~99.8% dead: 420 of its 421 entries contain an uppercase
/// character, so `IEX(New-Object Net.WebClient).DownloadString(...)` scored zero.
///
/// A fix for this was written and committed (7d17fe7, "@pm / @pmFromFile made
/// case-INSENSITIVE") — but it was applied to `patterns::PatternRegistry::ac_set`,
/// which had no callers anywhere in the workspace. The live path is here, and it
/// kept the old behaviour. The dead module has since been deleted so the fix
/// cannot land in the wrong place again.
///
/// Guarded by `tests/pm_case_insensitive.rs`.
pub fn build_ac(words: &[String]) -> anyhow::Result<AhoCorasick> {
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(words)
        .map_err(|e| anyhow::anyhow!("AhoCorasick build error: {e}"))
}
