pub mod v1 {
    use crate::apply_change;
    use crate::cache::read_or_fetch;
    use crate::parser::ShareConfig;
    use anyhow::Error;
    use axum::extract::Path;
    use axum::http::Response;
    use axum::response::IntoResponse;
    use log::error;
    use std::sync::Arc;
    use tokio::sync::RwLock;

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
        share_config: Arc<RwLock<ShareConfig>>,
    ) -> Result<Response<String>, ErrorCode> {
        let share_config = share_config.read().await;
        let mapper = share_config
            .search_url(&sub_id)
            .ok_or(ErrorCode::Forbidden)?;
        let redis_key = sha256::digest(mapper.as_str());
        let (content, remote_status) =
            read_or_fetch(mapper, redis_key, share_config.get_redis_connection().await).await?;
        let ret =
            apply_change(content, share_config).map_err(|e| error!("Apply change error: {:?}", e));
        let ret =
            serde_yaml::to_string(&ret).map_err(|e| error!("Serialize yaml failed: {:?}", e))?;
        let response = if remote_status.is_empty() {
            Response::builder()
        } else {
            Response::builder().header("subscription-userinfo", remote_status)
        }
        .header(
            "content-disposition",
            format!("attachment; filename=Clash_{}.yaml", sub_id),
        )
        .body(ret)
        .unwrap();
        Ok(response)
    }

    pub async fn get(
        Path(sub_id): Path<String>,
        share_configure: Arc<RwLock<ShareConfig>>,
    ) -> impl IntoResponse {
        match sub_process(sub_id, share_configure).await {
            Ok(response) => response,
            Err(code) => match code {
                ErrorCode::Forbidden => forbidden(),
                ErrorCode::InternalServerError => internal_server_error(),
                ErrorCode::NotAcceptable => not_acceptable(),
                ErrorCode::RequestTimeout => request_timeout(),
            },
        }
    }
}

pub use current::get;
pub use current::ErrorCode;
pub use v1 as current;
