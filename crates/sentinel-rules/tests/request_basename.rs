//! REQUEST_FILENAME is the request path; REQUEST_BASENAME is its last
//! component. The importer mapped both to the path, so CRS 942101 — which runs
//! libinjection over the file name — saw `/post/1234 OR 1=1`, whose `/post/`
//! prefix hides the injection, and CRS's own regression cases for it failed.

mod common;

use common::*;
use sentinel_core::context::Phase;
use sentinel_rules::RuleEngine;

fn engine(conf: &str) -> RuleEngine {
    let file = sentinel_rules::import_secrule_conf_dir(conf, None).expect("import rule");
    RuleEngine::new(sentinel_rules::compile(file).expect("compile rule"))
}

fn fired(eng: &RuleEngine, uri: &str, pl: u8) -> Vec<String> {
    let mut ctx = make_get_ctx(uri);
    set_paranoia(&mut ctx, pl);
    eval(eng, &mut ctx, Phase::RequestBody);
    ctx.rule_matches.iter().map(|m| m.rule_id.clone()).collect()
}

#[test]
fn the_two_variables_are_the_path_and_its_last_component() {
    let eng = engine(
        r#"
SecRule REQUEST_FILENAME "@streq /a/b.php" "id:1101,phase:1,block,msg:'path',setvar:'tx.inbound_anomaly_score_pl1=+5'"
SecRule REQUEST_BASENAME "@streq b.php" "id:1102,phase:1,block,msg:'base',setvar:'tx.inbound_anomaly_score_pl1=+5'"
SecRule REQUEST_BASENAME "@streq /a/b.php" "id:1103,phase:1,block,msg:'not the path',setvar:'tx.inbound_anomaly_score_pl1=+5'"
"#,
    );
    let ids = fired(&eng, "/a/b.php?x=1", 1);
    assert!(ids.contains(&"1101".to_string()), "{ids:?}");
    assert!(ids.contains(&"1102".to_string()), "{ids:?}");
    assert!(!ids.contains(&"1103".to_string()), "{ids:?}");
}

#[test]
fn rule_942101_sees_an_injection_in_the_last_path_segment() {
    let eng = load_crs_engines(&["REQUEST-942-APPLICATION-ATTACK-SQLI.conf"]);
    for uri in ["/post/1234%20OR%201=1", "/post/sleep(20)"] {
        let ids = fired(&eng, uri, 2);
        assert!(ids.contains(&"942101".to_string()), "{uri}: {ids:?}");
    }
    let ids = fired(&eng, "/post/index.html", 2);
    assert!(!ids.contains(&"942101".to_string()), "benign: {ids:?}");
}
