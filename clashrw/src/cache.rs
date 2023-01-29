mod cache {
    use crate::parser::{FileCache, RemoteConfigure};
    use crate::DISABLE_CACHE;
    use anyhow::anyhow;
    use log::error;
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

    fn parse_remote_configure(txt: &str) -> anyhow::Result<(RemoteConfigure, String)> {
        // TODO: Delete it
        let mut additional = txt
            .split('\n')
            .filter(|s| s.starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        additional.push('\n');

        let mut ret = serde_yaml::from_str::<RemoteConfigure>(txt)
            .map_err(|e| anyhow!("Got error while decode remote file: {:?}", e))?;

        ret.optimize();

        Ok((ret, additional))
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

    pub async fn read_or_fetch(url: &str) -> anyhow::Result<(RemoteConfigure, String)> {
        if Path::new(CACHE_FILE).exists() {
            if !DISABLE_CACHE.get().unwrap() {
                if let Some(cache) = read_cache().await {
                    if cache.check_is_cached() {
                        return parse_remote_configure(cache.content());
                    }
                }
            }
        }

        let cache = FileCache::new(
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
