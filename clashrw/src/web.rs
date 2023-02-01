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

    enum ErrorCode {
        Forbidden,
        InternalServerError,
    }

    impl From<()> for ErrorCode {
        fn from(_value: ()) -> Self {
            Self::InternalServerError
        }
    }

    impl From<anyhow::Error> for ErrorCode {
        fn from(_value: Error) -> Self {
            Self::from(())
        }
    }

    fn forbidden() -> Response<String> {
        let builder = Response::builder().status(403);
        builder.body("403 forbidden".to_string()).unwrap()
    }

    fn internal_server_error() -> Response<String> {
        let builder = Response::builder().status(500);
        builder
            .body("500 internal server error".to_string())
            .unwrap()
    }

    async fn sub_process(
        sub_id: String,
        share_config: Arc<ShareConfig>,
    ) -> Result<Response<String>, ErrorCode> {
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
        .body(ret)
        .unwrap();
        Ok(response)
    }

    pub async fn get(
        Path(sub_id): Path<String>,
        share_configure: Arc<ShareConfig>,
    ) -> impl IntoResponse {
        match sub_process(sub_id, share_configure).await {
            Ok(response) => response,
            Err(code) => match code {
                ErrorCode::Forbidden => forbidden(),
                ErrorCode::InternalServerError => internal_server_error(),
            },
        }
    }
}

pub use current::get;
pub use v1 as current;
