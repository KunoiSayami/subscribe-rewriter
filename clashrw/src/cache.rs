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
    use crate::DISABLE_CACHE;
    use anyhow::anyhow;
    use log::{debug, error, trace, warn};
    use redis::AsyncCommands;
    use std::time::Duration;

    pub const CACHE_TIME: usize = 600;

    async fn fetch_remote_file(url: &str) -> anyhow::Result<(String, String)> {
        let client = reqwest::ClientBuilder::new()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        let ret = client
            .get(url)
            .send()
            .await
            .map_err(|e| anyhow!("Get error while fetch remote file: {e:?}"))?;

        let header = ret
            .headers()
            .get("subscription-userinfo")
            .map(|v| v.to_str().unwrap_or_default().to_string())
            .unwrap_or_default();

        let txt = ret
            .text()
            .await
            .map_err(|e| anyhow!("Get error while obtain text: {e:?}"))?;

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
        if let Ok(ref mut redis_conn) = redis_conn {
            if !DISABLE_CACHE.get().unwrap() {
                let ret = redis_conn.exists(&redis_key).await.inspect_err(|e| {
                    warn!("[Can be safely ignored] Got error in query key {redis_key:?}: {e:?}")
                });
                if let Ok(ret) = ret {
                    if ret {
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
                            trace!("Cache: Content => {cache:?}");
                            return Ok((cache.content().to_string(), cache.remote_status()));
                        }
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

        if let Ok(redis_conn) = redis_conn {
            cache.write_to_redis(redis_key, redis_conn).await;
        }
        Ok((cache.content().to_string(), cache.remote_status()))
    }
}

pub use cache_::{parse_remote_configure, read_or_fetch, CACHE_TIME};
pub use file_cache::FileCache;
