pub mod v2 {
    use crate::apply_change;
    use crate::cache::{parse_remote_configure, read_or_fetch};
    use crate::parser::ShareConfig;
    use anyhow::Error;
    use axum::extract::{Path, Query};
    use axum::http::Response;
    use axum::response::IntoResponse;
    use axum::Extension;
    use log::error;
    use serde::Deserialize;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[derive(Deserialize)]
    pub struct QueryParams {
        method: Option<String>,
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
        share_config: Arc<RwLock<ShareConfig>>,
    ) -> Result<Response<String>, ErrorCode> {
        let share_config = share_config.read().await;

        let mapper = share_config
            .search_url(&sub_id)
            .ok_or(ErrorCode::Forbidden)?;

        let redis_key = if !method.eq("raw") {
            sha256::digest(mapper.upstream())
        } else {
            sha256::digest(format!("{}raw", mapper.upstream()))
        };

        let remote_url = if method.eq("raw") {
            if let Some(s) = mapper.raw() {
                s.as_str()
            } else {
                mapper.upstream()
            }
        } else {
            mapper.upstream()
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

        let ret = if !method.eq("raw") {
            let ret = apply_change(parse_remote_configure(&content)?, share_config)
                .inspect_err(|e| error!("Apply change error: {e:?}"))?;

            serde_yaml::to_string(&ret).map_err(|e| error!("Serialize yaml failed: {e:?}"))?
        } else {
            content
        };

        let response = if remote_status.is_empty() {
            Response::builder()
        } else {
            Response::builder().header("subscription-userinfo", remote_status)
        }
        .header(
            "content-disposition",
            format!("attachment; filename=Clash_{sub_id}.yaml"),
        )
        .body(ret)
        .unwrap();
        Ok(response)
    }

    pub async fn get(
        Path(sub_id): Path<String>,
        Extension(share_configure): Extension<Arc<RwLock<ShareConfig>>>,
        params: Query<QueryParams>,
    ) -> impl IntoResponse {
        sub_process(
            sub_id,
            &params.method.clone().unwrap_or_default(),
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

pub use current::get;
pub use current::ErrorCode;
pub use v2 as current;
