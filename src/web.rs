pub mod v2 {
    use crate::apply_change;
    use crate::cache::{parse_remote_configure, read_or_fetch, read_srs_cache, write_srs_cache};
    use crate::parser::ShareConfig;
    use crate::ruleset;
    use anyhow::{Context, Error};
    use axum::Extension;
    use axum::extract::{Path, Query};
    use axum::http::Response;
    use axum::response::IntoResponse;
    use log::error;
    use serde::Deserialize;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[derive(Deserialize)]
    pub struct QueryParams {
        method: Option<String>,
        log: Option<String>,
    }

    #[derive(Clone)]
    pub enum ErrorCode {
        Forbidden,
        InternalServerError,
        RequestTimeout,
        NotAcceptable,
    }

    impl From<()> for ErrorCode {
        fn from(_value: ()) -> Self {
            Self::InternalServerError
        }
    }

    impl From<Error> for ErrorCode {
        fn from(_value: Error) -> Self {
            Self::from(())
        }
    }

    fn build_body(code: u16, msg: &str) -> Response<String> {
        let builder = Response::builder().status(code);
        builder.body(msg.to_string()).unwrap()
    }

    fn forbidden() -> Response<String> {
        build_body(403, "403 forbidden")
    }

    fn internal_server_error() -> Response<String> {
        build_body(500, "500 internal server error")
    }

    fn request_timeout() -> Response<String> {
        build_body(408, "408 Request Timeout")
    }

    fn not_acceptable() -> Response<String> {
        build_body(406, "406 Not Acceptable")
    }

    async fn sub_process(
        sub_id: String,
        method: &str,
        log_level: Option<String>,
        share_config: Arc<RwLock<ShareConfig>>,
    ) -> Result<Response<String>, ErrorCode> {
        let share_config = share_config.read().await;

        let mapper = share_config
            .search_url(&sub_id)
            .ok_or(ErrorCode::Forbidden)?;

        let (redis_key, remote_url) = if method.eq("singbox") {
            let url = mapper.singbox().ok_or(ErrorCode::NotAcceptable)?;
            (format!("sr-singbox{}", sha256::digest(url)), url)
        } else if method.eq("raw")
            && let Some(s) = mapper.raw()
        {
            (format!("sr-raw{}", sha256::digest(mapper.upstream())), s)
        } else {
            (sha256::digest(mapper.upstream()), mapper.upstream())
        };

        let (content, remote_status) = read_or_fetch(
            remote_url,
            redis_key,
            share_config.get_redis_connection().await,
        )
        .await?;

        let remote_status = if let Some(rewrite_config) = mapper.sub_override() {
            rewrite_config.rewrite(remote_status)
        } else {
            remote_status
        };

        let (ret, filename) = if sub_id.eq("sample") {
            let mut remote = parse_remote_configure(&content)?;
            remote
                .mut_proxies()
                .set_vec(vec![crate::parser::Proxy::stub_value()]);
            (
                serde_yaml::to_string(&remote).context("Serialize yaml failed")?,
                format!("attachment; filename=Clash_sample.yaml"),
            )
        } else if method.eq("singbox") {
            let mut cfg = crate::singbox::convert(
                &content,
                share_config.singbox_base_for(&sub_id),
                share_config.proxies().get_vec(),
                &share_config.rules().get_element(),
                share_config.manual_insert_proxies(),
                share_config.singbox_direct_tag(),
            );
            if let Some(level) = log_level {
                let level = match level.to_ascii_lowercase().as_str() {
                    v @ ("trace" | "debug" | "info" | "warn" | "error" | "fatal" | "panic") => {
                        v.to_string()
                    }
                    _ => "info".to_string(),
                };
                cfg["log"]["level"] = serde_json::json!(level);
            }
            let json =
                serde_json::to_string_pretty(&cfg).context("Serialize singbox json failed")?;
            (json, format!("attachment; filename=singbox_{sub_id}.json"))
        } else if !method.eq("raw") && !mapper.passthrough() {
            let ret = apply_change(&sub_id, parse_remote_configure(&content)?, share_config)
                .inspect_err(|e| error!("Apply change error: {e:?}"))?;
            (
                serde_yaml::to_string(&ret).context("Serialize yaml failed")?,
                format!("attachment; filename=Clash_{sub_id}.yaml"),
            )
        } else {
            (content, format!("attachment; filename=Clash_{sub_id}.yaml"))
        };

        let response = if remote_status.is_empty() {
            Response::builder()
        } else {
            Response::builder().header("subscription-userinfo", remote_status)
        }
        .header("content-disposition", filename)
        .body(ret)
        .unwrap();
        Ok(response)
    }

    fn bytes_error(code: u16, msg: &'static str) -> Response<axum::body::Body> {
        Response::builder()
            .status(code)
            .body(axum::body::Body::from(msg))
            .unwrap()
    }

    #[derive(Deserialize)]
    pub struct RuleSetParams {
        raw: Option<String>,
    }

    pub async fn get_rule_set(
        Path(tag): Path<String>,
        Extension(share_configure): Extension<Arc<RwLock<ShareConfig>>>,
        params: Query<RuleSetParams>,
    ) -> impl IntoResponse {
        let (tag, return_raw) = if let Some(stem) = tag.strip_suffix(".json") {
            (stem.to_string(), true)
        } else if let Some(stem) = tag.strip_suffix(".srs") {
            (stem.to_string(), false)
        } else {
            (tag, params.raw.is_some())
        };

        let (url, add, remove, bin_path) = {
            let cfg = share_configure.read().await;
            let entry = cfg
                .singbox_rule_sets()
                .iter()
                .find(|e| e.tag() == tag)
                .map(|e| (e.url().to_string(), e.add().to_vec(), e.remove().cloned()));
            match entry {
                Some((url, add, remove)) => {
                    (url, add, remove, cfg.singbox_bin_path().map(str::to_owned))
                }
                None => return bytes_error(404, "404 not found"),
            }
        };

        // Cache key covers the URL and all local patches so any config change busts the cache.
        let patch_digest = sha256::digest(format!("{url}{add:?}{remove:?}"));
        let srs_cache_key = format!("sr-srs-{patch_digest}");

        let mut redis_conn = match share_configure.read().await.get_redis_connection().await {
            Ok(c) => c,
            Err(e) => {
                error!("Redis connection for rule-set {tag}: {e:?}");
                return bytes_error(500, "500 internal server error");
            }
        };

        if !return_raw {
            if let Some(cached) = read_srs_cache(&srs_cache_key, &mut redis_conn).await {
                return Response::builder()
                    .header("content-type", "application/octet-stream")
                    .header(
                        "content-disposition",
                        format!("attachment; filename={tag}.srs"),
                    )
                    .body(axum::body::Body::from(cached))
                    .unwrap();
            }
        }

        let (content, _) = match read_or_fetch(
            &url,
            format!("sr-ruleset-src-{}", sha256::digest(&url)),
            Ok(redis_conn.clone()),
        )
        .await
        {
            Ok(v) => v,
            Err(_) => return bytes_error(500, "500 internal server error"),
        };

        let mut source: serde_json::Value = match json5::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                error!("Parse rule-set source JSON: {e:?}");
                return bytes_error(500, "500 internal server error");
            }
        };

        ruleset::patch_rule_set_source(&mut source, &add, remove.as_ref());

        if return_raw {
            let json = match serde_json::to_string_pretty(&source) {
                Ok(s) => s,
                Err(e) => {
                    error!("Serialize rule-set JSON for {tag}: {e:?}");
                    return bytes_error(500, "500 internal server error");
                }
            };
            return Response::builder()
                .header("content-type", "application/json")
                .header(
                    "content-disposition",
                    format!("attachment; filename={tag}.json"),
                )
                .body(axum::body::Body::from(json))
                .unwrap();
        }

        let bytes = match ruleset::compile_to_srs(&source, bin_path.as_deref()).await {
            Ok(b) => b,
            Err(e) => {
                error!("Compile rule-set {tag}: {e:?}");
                return bytes_error(500, "500 internal server error");
            }
        };

        write_srs_cache(&srs_cache_key, &bytes, redis_conn).await;

        Response::builder()
            .header("content-type", "application/octet-stream")
            .header(
                "content-disposition",
                format!("attachment; filename={tag}.srs"),
            )
            .body(axum::body::Body::from(bytes))
            .unwrap()
    }

    pub async fn get(
        Path(sub_id): Path<String>,
        Extension(share_configure): Extension<Arc<RwLock<ShareConfig>>>,
        params: Query<QueryParams>,
    ) -> impl IntoResponse {
        sub_process(
            sub_id,
            &params.method.clone().unwrap_or_default(),
            params.log.clone(),
            share_configure,
        )
        .await
        .unwrap_or_else(|code| match code {
            ErrorCode::Forbidden => forbidden(),
            ErrorCode::InternalServerError => internal_server_error(),
            ErrorCode::NotAcceptable => not_acceptable(),
            ErrorCode::RequestTimeout => request_timeout(),
        })
    }
}

pub use current::ErrorCode;
pub use current::get;
pub use current::get_rule_set;
pub use v2 as current;
