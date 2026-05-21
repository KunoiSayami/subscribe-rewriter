use crate::parser::RuleSetRemove;
use crate::singbox::parse_clash_rule;
use anyhow::Context;
use serde_json::Value;
use std::io::Write;
use tempfile::NamedTempFile;

const RULE_FIELDS: &[&str] = &[
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "ip_cidr",
];

/// Apply local `add` and `remove` overrides to a fetched sing-box rule-set source JSON.
///
/// The expected structure is `{ "version": N, "rules": [ { "domain": [...], ... } ] }`.
/// `add` entries are Clash-style rule strings (outbound field is ignored).
/// `remove.keyword` strips any value containing the keyword; `remove.rules` strips exact matches.
pub fn patch_rule_set_source(source: &mut Value, add: &[String], remove: Option<&RuleSetRemove>) {
    let rules = source
        .get_mut("rules")
        .and_then(|v| v.as_array_mut())
        .filter(|a| !a.is_empty());

    let Some(rules) = rules else {
        return;
    };

    let rule_obj = rules[0].as_object_mut();
    let Some(rule_obj) = rule_obj else {
        return;
    };

    // Apply removes first so adds are never accidentally removed.
    if let Some(rem) = remove {
        for field in RULE_FIELDS {
            if let Some(arr) = rule_obj.get_mut(*field).and_then(|v| v.as_array_mut()) {
                if !rem.keyword.is_empty() {
                    arr.retain(|v| {
                        let s = v.as_str().unwrap_or("");
                        !rem.keyword.iter().any(|kw| s.contains(kw.as_str()))
                    });
                }
                if !rem.rules.is_empty() {
                    let exact: std::collections::HashSet<String> = rem
                        .rules
                        .iter()
                        .filter_map(|r| {
                            let parsed = parse_clash_rule(r)?;
                            if parsed.field == *field {
                                Some(parsed.value)
                            } else {
                                None
                            }
                        })
                        .collect();
                    if !exact.is_empty() {
                        arr.retain(|v| !exact.contains(v.as_str().unwrap_or("")));
                    }
                }
            }
        }
    }

    // Apply additions.
    for entry in add {
        let Some(parsed) = parse_clash_rule(entry) else {
            continue;
        };
        let arr = rule_obj
            .entry(parsed.field)
            .or_insert_with(|| Value::Array(vec![]));
        if let Some(a) = arr.as_array_mut() {
            a.push(Value::String(parsed.value));
        }
    }
}

/// Compile a sing-box rule-set source JSON to binary `.srs` bytes by invoking
/// `sing-box rule-set compile`. `bin_path` overrides the executable; falls back to PATH lookup.
pub async fn compile_to_srs(source: &Value, bin_path: Option<&str>) -> anyhow::Result<Vec<u8>> {
    let mut input = NamedTempFile::with_suffix(".json").context("create temp input file")?;
    let json_bytes = serde_json::to_vec(source).context("serialize rule-set source")?;
    input
        .write_all(&json_bytes)
        .context("write temp input file")?;
    input.flush().context("flush temp input file")?;

    let output = NamedTempFile::with_suffix(".srs").context("create temp output file")?;
    let input_path = input.path().to_owned();
    let output_path = output.path().to_owned();

    let exe = bin_path.unwrap_or("sing-box");
    let result = tokio::process::Command::new(exe)
        .args([
            "rule-set",
            "compile",
            input_path.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
        ])
        .output()
        .await
        .with_context(|| format!("spawn {exe}"))?;

    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        anyhow::bail!("{exe} rule-set compile failed: {stderr}");
    }

    let bytes = tokio::fs::read(&output_path)
        .await
        .context("read compiled .srs")?;

    Ok(bytes)
}
