use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let subscription = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("sample.txt"));
    let base_config = args.next().map(PathBuf::from);

    let raw = std::fs::read_to_string(&subscription)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", subscription.display()));

    let base = base_config.as_deref().map(|p| {
        let s = std::fs::read_to_string(p)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
        serde_json::from_str::<serde_json::Value>(&s)
            .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", p.display()))
    });

    let result = subscribe_rewriter::singbox::convert(&raw, base.as_ref(), &[], &[]);
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
