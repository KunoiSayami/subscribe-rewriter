mod file_cache {
    use crate::cache::CACHE_TIME;
    use log::error;
    use redis::AsyncCommands;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct FileCache {
        remote_status: String,
        content: String,
    }

    impl FileCache {
        pub fn content(&self) -> &str {
            &self.content
        }

        pub fn new(content: (String, String)) -> Self {
            Self {
                remote_status: content.1,
                content: content.0,
            }
        }

        pub async fn write_to_redis(
            &self,
            redis_key: String,
            mut redis_conn: redis::aio::MultiplexedConnection,
        ) {
            if let Ok(s) = serde_yaml::to_string(self)
                .inspect_err(|e| error!("[Can be safely ignored] Serialize cache_ error: {e:?}"))
            {
                redis_conn
                    .set_ex::<_, String, String>(&redis_key, s, CACHE_TIME as u64)
                    .await
                    .inspect_err(|e| error!("[Can be safely ignored] Write to redis error: {e:?}"))
                    .ok();
            }
        }
        pub fn remote_status(&self) -> String {
            self.remote_status.clone()
        }
    }
}

mod cache_ {
    use super::FileCache;
    use crate::parser::RemoteConfigure;
    use crate::web::ErrorCode;
    use crate::{DISABLE_CACHE, SHOW_CACHE};
    use anyhow::Context;
    use log::{debug, error, trace, warn};
    use redis::AsyncCommands;
    use std::sync::OnceLock;
    use std::time::Duration;

    pub const CACHE_TIME: usize = 600;
    pub const RULESET_CACHE_TIME: usize = 86400;

    static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

    fn http_client() -> &'static reqwest::Client {
        HTTP_CLIENT.get_or_init(|| {
            reqwest::ClientBuilder::new()
                .timeout(Duration::from_secs(10))
                .user_agent("curl/8.19.0")
                .build()
                .unwrap()
        })
    }

    async fn fetch_remote_file(url: &str) -> anyhow::Result<(String, String)> {
        let ret = http_client()
            .get(url)
            .send()
            .await
            .context("fetch remote file")?;

        let header = ret
            .headers()
            .get("subscription-userinfo")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();

        let txt = ret.text().await.context("obtain text")?;

        Ok((txt, header))
    }

    pub fn parse_remote_configure(txt: &str) -> Result<RemoteConfigure, ErrorCode> {
        let mut ret = serde_yaml::from_str::<RemoteConfigure>(txt).map_err(|e| {
            error!("Got error while decode remote file: {e:?}");
            trace!("Remote file: {txt:?}");
            ErrorCode::NotAcceptable
        })?;

        ret.optimize();

        Ok(ret)
    }

    fn read_cache(content: Option<String>) -> Option<FileCache> {
        serde_yaml::from_str(content?.as_str())
            .inspect_err(|e| {
                warn!("[Can be safely ignored] Got error while serialize cache_ yaml: {e:?}")
            })
            .ok()
    }

    pub async fn read_or_fetch(
        url: &str,
        redis_key: String,
        mut redis_conn: anyhow::Result<redis::aio::MultiplexedConnection>,
    ) -> Result<(String, String), ErrorCode> {
        let local = std::path::Path::new(url);
        if local.exists() && local.is_file() {
            let content = std::fs::read_to_string(local).map_err(|e| {
                error!("Failed to read local file {url:?}: {e:?}");
                ErrorCode::InternalServerError
            })?;
            return Ok((content, String::new()));
        }

        if let Ok(ref mut redis_conn) = redis_conn {
            if !DISABLE_CACHE.get().unwrap() {
                let ret = redis_conn.exists(&redis_key).await.inspect_err(|e| {
                    warn!("[Can be safely ignored] Got error in query key {redis_key:?}: {e:?}")
                });
                if let Ok(ret) = ret
                    && ret
                {
                    let cache = redis_conn
                            .get::<_, Option<String>>(&redis_key)
                            .await
                            .inspect_err(|e| {
                                warn!(
                                    "[Can be safely ignored] Got error in fetch key {redis_key:?}: {e:?}"
                                )
                            })
                            .ok().flatten();
                    if let Some(cache) = read_cache(cache) {
                        debug!("Cache: Read from cache");
                        if *SHOW_CACHE.get().unwrap_or(&false) {
                            trace!("Cache: Content => {cache:?}");
                        }
                        return Ok((cache.content().to_string(), cache.remote_status()));
                    }
                }
            }
        } else if let Err(ref e) = redis_conn {
            warn!("[Can be safely ignored] can't get redis connection: {e:?}");
        }

        let cache = FileCache::new(fetch_remote_file(url).await.map_err(|e| {
            error!("Get error while fetch remote file: {e:?}");
            ErrorCode::RequestTimeout
        })?);

        //log::trace!("{redis_key}");

        if let Ok(redis_conn) = redis_conn
            && (!redis_key.starts_with("sr-")
                && parse_remote_configure(cache.content()).is_ok_and(|x| x.proxies_len() > 0))
        {
            cache.write_to_redis(redis_key, redis_conn).await;
        }
        Ok((cache.content().to_string(), cache.remote_status()))
    }

    /// Read compiled `.srs` bytes from Redis. Returns `None` on miss or cache disabled.
    pub async fn read_srs_cache(
        redis_key: &str,
        redis_conn: &mut redis::aio::MultiplexedConnection,
    ) -> Option<Vec<u8>> {
        if *DISABLE_CACHE.get().unwrap_or(&false) {
            return None;
        }
        redis_conn
            .get::<_, Option<Vec<u8>>>(redis_key)
            .await
            .inspect_err(|e| warn!("[Can be safely ignored] read srs cache {redis_key:?}: {e:?}"))
            .ok()
            .flatten()
    }

    /// Write compiled `.srs` bytes to Redis with `RULESET_CACHE_TIME` TTL.
    pub async fn write_srs_cache(
        redis_key: &str,
        bytes: &[u8],
        redis_conn: redis::aio::MultiplexedConnection,
    ) {
        if *DISABLE_CACHE.get().unwrap_or(&false) {
            return;
        }
        let mut conn = redis_conn;
        conn.set_ex::<_, &[u8], ()>(redis_key, bytes, RULESET_CACHE_TIME as u64)
            .await
            .inspect_err(|e| warn!("[Can be safely ignored] write srs cache {redis_key:?}: {e:?}"))
            .ok();
    }
}

pub use cache_::{
    CACHE_TIME, parse_remote_configure, read_or_fetch, read_srs_cache, write_srs_cache,
};
pub use file_cache::FileCache;
