use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sentinel_core::context::{Phase, RequestContext};
use sentinel_rules::dsl::ast::Operator;
use sentinel_rules::dsl::ast::{
    RuleAction, RuleDef, RuleFile, RuleItem, RulePhase, RuleSeverity, Target, TargetExpr,
};
use sentinel_rules::{compile, RuleEngine};

use std::net::{IpAddr, Ipv4Addr};

/// Generate a RuleFile with `n` simple regex rules.
/// All rules target ARGS and match a distinct pattern,
/// score +5 on match, action score.
fn build_rules(n: usize) -> RuleFile {
    let rules: Vec<RuleItem> = (0..n)
        .map(|i| {
            RuleItem::Rule(RuleDef {
                id: i as u32,
                phase: RulePhase::RequestBody,
                targets: vec![TargetExpr {
                    target: Target::Args,
                    combinator: None,
                }],
                operator: Operator::Rx(format!("(?i)attack_pattern_{i}")),
                score_delta: Some(5),
                severity: Some(RuleSeverity::Critical),
                message: Some(format!("Rule {i}")),
                action: RuleAction::Score,
                tags: vec![],
                chain_conditions: vec![],
                transforms: vec![],
                skip_after: None,
                multi_match: false,
                setvars: vec![],
                exclusions: vec![],
                remove_targets: vec![],
                remove_targets_by_tag: vec![],
            })
        })
        .collect();
    RuleFile { items: rules }
}

/// Clean request — contains no attack patterns, no rules fire.
fn clean_ctx() -> RequestContext {
    let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
    ctx.uri = "http://example.com/?name=John&city=NYC&page=1"
        .parse()
        .unwrap();
    ctx
}

/// Malicious request — matches the first few rules (will push anomaly score to 10).
fn malicious_ctx() -> RequestContext {
    let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
    ctx.uri = "http://example.com/?q=attack_pattern_0&x=attack_pattern_1"
        .parse()
        .unwrap();
    ctx
}

fn bench_clean_no_early_exit(c: &mut Criterion) {
    let file = build_rules(200);
    let ruleset = compile(file).unwrap();
    let engine = RuleEngine::new(ruleset);

    c.bench_function(
        &format!("vm_clean_{}_no_early_exit", engine.rule_count()),
        |b| {
            b.iter(|| {
                let mut ctx = clean_ctx();
                black_box(engine.evaluate(
                    black_box(&mut ctx),
                    black_box(Phase::RequestBody),
                    black_box(0),
                ));
                black_box(&ctx);
            })
        },
    );
}

fn bench_clean_with_early_exit(c: &mut Criterion) {
    let file = build_rules(200);
    let ruleset = compile(file).unwrap();
    let engine = RuleEngine::new(ruleset);

    c.bench_function(
        &format!("vm_clean_{}_early_exit_threshold=5", engine.rule_count()),
        |b| {
            b.iter(|| {
                let mut ctx = clean_ctx();
                black_box(engine.evaluate(
                    black_box(&mut ctx),
                    black_box(Phase::RequestBody),
                    black_box(5),
                ));
                black_box(&ctx);
            })
        },
    );
}

fn bench_malicious_no_early_exit(c: &mut Criterion) {
    let file = build_rules(200);
    let ruleset = compile(file).unwrap();
    let engine = RuleEngine::new(ruleset);

    c.bench_function(
        &format!("vm_malicious_{}_no_early_exit", engine.rule_count()),
        |b| {
            b.iter(|| {
                let mut ctx = malicious_ctx();
                black_box(engine.evaluate(
                    black_box(&mut ctx),
                    black_box(Phase::RequestBody),
                    black_box(0),
                ));
                black_box(&ctx);
            })
        },
    );
}

fn bench_malicious_with_early_exit(c: &mut Criterion) {
    let file = build_rules(200);
    let ruleset = compile(file).unwrap();
    let engine = RuleEngine::new(ruleset);

    c.bench_function(
        &format!(
            "vm_malicious_{}_early_exit_threshold=5",
            engine.rule_count()
        ),
        |b| {
            b.iter(|| {
                let mut ctx = malicious_ctx();
                black_box(engine.evaluate(
                    black_box(&mut ctx),
                    black_box(Phase::RequestBody),
                    black_box(5),
                ));
                black_box(&ctx);
            })
        },
    );
}

fn bench_varying_rule_counts(c: &mut Criterion) {
    for n in [50, 100, 200, 500] {
        let file = build_rules(n);
        let ruleset = compile(file).unwrap();
        let engine = RuleEngine::new(ruleset);

        // Clean traffic — no early exit can help
        c.bench_function(&format!("vm_clean_{n}r_clean_input"), |b| {
            b.iter(|| {
                let mut ctx = clean_ctx();
                black_box(engine.evaluate(
                    black_box(&mut ctx),
                    black_box(Phase::RequestBody),
                    black_box(0),
                ));
                black_box(&ctx);
            })
        });

        // Malicious traffic with early exit
        c.bench_function(&format!("vm_malicious_{n}r_early_exit"), |b| {
            b.iter(|| {
                let mut ctx = malicious_ctx();
                black_box(engine.evaluate(
                    black_box(&mut ctx),
                    black_box(Phase::RequestBody),
                    black_box(5),
                ));
                black_box(&ctx);
            })
        });
    }
}

criterion_group!(
    benches,
    bench_clean_no_early_exit,
    bench_clean_with_early_exit,
    bench_malicious_no_early_exit,
    bench_malicious_with_early_exit,
    bench_varying_rule_counts,
);
criterion_main!(benches);
