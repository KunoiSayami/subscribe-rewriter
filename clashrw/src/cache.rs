mod file_cache {
    use crate::cache::CACHE_TIME;
    use serde_derive::{Deserialize, Serialize};
    use tokio::io::AsyncWriteExt;

    pub fn get_current_timestamp() -> u64 {
        let start = std::time::SystemTime::now();
        let since_the_epoch = start
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards");
        since_the_epoch.as_secs()
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct FileCache {
        timestamp: u64,
        url: String,
        content: String,
    }

    impl FileCache {
        pub fn content(&self) -> &str {
            &self.content
        }

        pub fn new(url: String, content: String) -> Self {
            Self {
                timestamp: get_current_timestamp(),
                url,
                content,
            }
        }

        pub fn check_is_cached(&self) -> bool {
            get_current_timestamp() - self.timestamp <= CACHE_TIME
        }

        pub async fn write_to_file(&self, path: &str) -> anyhow::Result<()> {
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(path)
                .await?;
            file.write_all(serde_yaml::to_string(self)?.as_bytes())
                .await?;
            Ok(())
        }

        pub fn url(&self) -> &str {
            &self.url
        }
    }
}

mod cache {
    use super::FileCache;
    use crate::parser::RemoteConfigure;
    use crate::DISABLE_CACHE;
    use anyhow::anyhow;
    use log::{debug, error};
    use std::path::Path;

    pub const CACHE_FILE: &str = ".cache.yaml";
    pub const CACHE_TIME: u64 = 600;

    async fn fetch_remote_file(url: &str) -> anyhow::Result<String> {
        let client = reqwest::ClientBuilder::new().build().unwrap();
        let ret = client
            .get(url)
            .send()
            .await
            .map_err(|e| anyhow!("Get error while fetch remote file: {:?}", e))?;

        let txt = ret
            .text()
            .await
            .map_err(|e| anyhow!("Get error while obtain text: {:?}", e))?;

        Ok(txt)
    }

    fn parse_remote_configure(txt: &str) -> anyhow::Result<RemoteConfigure> {
        let mut ret = serde_yaml::from_str::<RemoteConfigure>(txt)
            .map_err(|e| anyhow!("Got error while decode remote file: {:?}", e))?;

        ret.optimize();

        Ok(ret)
    }

    async fn read_cache() -> Option<FileCache> {
        let content = tokio::fs::read_to_string(CACHE_FILE)
            .await
            .map_err(|e| {
                error!(
                    "[Can be safely ignored] Got error while read cache: {:?}",
                    e
                )
            })
            .ok()?;
        serde_yaml::from_str(content.as_str())
            .map_err(|e| {
                error!(
                    "[Can be safely ignored] Got error while serialize cache yaml: {:?}",
                    e
                )
            })
            .ok()
    }

    pub async fn read_or_fetch(url: &str) -> anyhow::Result<RemoteConfigure> {
        if Path::new(CACHE_FILE).exists() {
            if !DISABLE_CACHE.get().unwrap() {
                if let Some(cache) = read_cache().await {
                    if url.eq(cache.url()) && cache.check_is_cached() {
                        debug!("Cache: Read from cache");
                        return parse_remote_configure(cache.content());
                    }
                }
            }
        }

        let cache = FileCache::new(
            url.to_string(),
            fetch_remote_file(url)
                .await
                .map_err(|e| anyhow!("Get error while fetch remote file: {:?}", e))?,
        );

        cache
            .write_to_file(CACHE_FILE)
            .await
            .map_err(|e| error!("[Can be safely ignored] Write cache fail: {:?}", e))
            .ok();

        parse_remote_configure(cache.content())
    }
}

pub use cache::{read_or_fetch, CACHE_TIME};
pub use file_cache::FileCache;
