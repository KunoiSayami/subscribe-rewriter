use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let subscription = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("sample.txt"));
    let base_config = args.next().map(PathBuf::from);
    let local_config = args.next().map(PathBuf::from);

    let raw = std::fs::read_to_string(&subscription)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", subscription.display()));

    let base = base_config.as_deref().map(|p| {
        let s = std::fs::read_to_string(p)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
        json5::from_str::<serde_json::Value>(&s)
            .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", p.display()))
    });

    let (extra, clash_rules, placeholder_detour, direct_tag) = if let Some(p) = local_config {
        let s = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
        let cfg: serde_yaml::Value = serde_yaml::from_str(&s)
            .unwrap_or_else(|e| panic!("invalid YAML in {}: {e}", p.display()));

        let proxies = cfg["proxies"].as_sequence().cloned().unwrap_or_default();

        let rules = cfg["rules"]
            .as_sequence()
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let groups = cfg["manual_add_group_name"]
            .as_sequence()
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let direct_tag = cfg["singbox"]["direct_tag"]
            .as_str()
            .unwrap_or("direct")
            .to_string();

        (proxies, rules, groups, direct_tag)
    } else {
        (vec![], vec![], vec![], "direct".to_string())
    };

    let result = subscribe_rewriter::singbox::convert(
        &raw,
        base.as_ref(),
        &extra,
        &clash_rules,
        &placeholder_detour,
        &direct_tag,
    );
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
