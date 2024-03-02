mod proxies {
    use super::{Deserialize, Serialize};

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct Proxy {
        name: String,
        #[serde(rename = "type")]
        type_: String,
        server: String,
        port: u16,
        cipher: String,
        #[serde(default)]
        password: String,
        udp: bool,
    }

    impl Proxy {
        pub fn password(&self) -> &str {
            &self.password
        }

        pub fn is_empty_password(value: serde_yaml::Value) -> Option<String> {
            let proxy: Self = serde_yaml::from_value(value).ok()?;
            if proxy.password().is_empty() {
                Some(proxy.name)
            } else {
                None
            }
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct Proxies(pub Vec<serde_yaml::Value>);

    impl Proxies {
        pub fn get_vec(&self) -> &Vec<serde_yaml::Value> {
            &self.0
        }

        pub fn set_vec(&mut self, v: Vec<serde_yaml::Value>) -> &mut Self {
            self.0 = v;
            self
        }
    }
}

mod proxy_groups {
    use super::{Deserialize, Serialize};
    use crate::DIRECT_NAME;

    #[derive(Clone, Debug, Default, Deserialize, Serialize)]
    pub struct ProxyGroup {
        name: String,
        #[serde(rename = "type")]
        type_: String,
        proxies: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        url: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        interval: Option<u64>,
    }

    impl ProxyGroup {
        #[allow(unused)]
        pub fn name(&self) -> &str {
            &self.name
        }
        pub fn group_type(&self) -> &str {
            &self.type_
        }
        pub fn proxies(&self) -> &Vec<String> {
            &self.proxies
        }

        pub fn remove(&mut self, index: usize) -> &mut Self {
            self.proxies.remove(index);
            self
        }

        #[allow(unused)]
        pub fn new_relay(name: String, first: String, second: String) -> Self {
            Self {
                name,
                type_: "relay".to_string(),
                proxies: vec![first, second],
                ..Default::default()
            }
        }

        pub fn new_select(name: String, proxies: Vec<String>) -> Self {
            Self {
                name,
                type_: "select".to_string(),
                proxies,
                ..Default::default()
            }
        }

        #[allow(unused)]
        pub fn new_url_test(name: String, proxies: Vec<String>, url: String) -> Self {
            Self {
                name,
                type_: "url-test".to_string(),
                proxies,
                url: Some(url),
                interval: Some(600),
            }
        }

        /*pub fn insert_to_head(&mut self, proxy: String) -> &mut Self {
            self.insert(0, proxy);
            self
        }*/

        pub fn insert(&mut self, index: usize, proxy: String) -> &mut Self {
            self.proxies.insert(index, proxy);
            self
        }

        pub fn insert_direct(mut self) -> Self {
            debug_assert!({
                if let Some(proxy) = self.proxies.last() {
                    !proxy.eq(DIRECT_NAME)
                } else {
                    true
                }
            });
            self.proxies.push(DIRECT_NAME.to_string());
            self
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct ProxyGroups(pub Vec<ProxyGroup>);

    impl ProxyGroups {
        pub fn get_vec(&self) -> &Vec<ProxyGroup> {
            &self.0
        }

        /*pub fn get_mut_vec(&mut self) -> &mut Vec<ProxyGroup> {
            &mut self.0
        }*/

        pub fn set_vec(&mut self, v: Vec<ProxyGroup>) -> &mut Self {
            self.0 = v;
            self
        }
    }
}

mod rules {

    use super::{Deserialize, Serialize};

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct Rules(Vec<String>);

    impl Rules {
        pub fn insert_head(&mut self, mut from: Vec<String>) -> &mut Self {
            from.extend(self.0.iter().cloned());
            self.0 = from;
            self
        }

        pub fn get_element(&self) -> Vec<String> {
            self.0.clone()
        }
    }
}
mod remote_configure {
    use super::{Proxies, ProxyGroups, Rules};
    use crate::parser::proxies::Proxy;
    use log::info;

    use super::{Deserialize, Serialize};

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct RemoteConfigure {
        #[serde(default = "default_port")]
        port: u16,
        #[serde(rename = "socks-port", default = "default_socks_port")]
        socks_port: u16,
        #[serde(rename = "redir-port", default = "default_redir_port")]
        redir_port: u16,
        #[serde(rename = "allow-lan", default)]
        allow_lan: bool,
        mode: String,
        #[serde(rename = "log-level")]
        log_level: String,
        #[serde(rename = "external-controller")]
        external_controller: String,
        #[serde(default)]
        secret: String,
        proxies: Proxies,
        #[serde(rename = "proxy-groups")]
        proxy_groups: ProxyGroups,
        rules: Rules,
    }

    impl RemoteConfigure {
        pub fn proxy_groups(&self) -> &ProxyGroups {
            &self.proxy_groups
        }
        pub fn mut_proxy_groups(&mut self) -> &mut ProxyGroups {
            &mut self.proxy_groups
        }
        pub fn mut_rules(&mut self) -> &mut Rules {
            &mut self.rules
        }
        pub fn mut_proxies(&mut self) -> &mut Proxies {
            &mut self.proxies
        }

        pub fn optimize(&mut self) -> &mut Self {
            let mut v = vec![];
            for element in &self.proxies.0 {
                if let Some(name) = Proxy::is_empty_password(element.clone()) {
                    v.push(name);
                }
            }
            for element in &mut self.proxy_groups.0 {
                for item in &v {
                    let ret = element.proxies().iter().position(|x| x.eq(item));
                    if ret.is_none() {
                        //warn!("Not found: {:?}", item);
                        continue;
                    }
                    element.remove(ret.unwrap());
                }
            }
            info!("Remove {} empty password elements.", v.len());
            self
        }
    }

    fn default_port() -> u16 {
        7890
    }

    fn default_redir_port() -> u16 {
        7892
    }

    fn default_socks_port() -> u16 {
        7891
    }
}

#[allow(unused)]
mod keyword {
    use super::{Deserialize, Serialize};

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct Keyword {
        filter: Vec<String>,
        accepted: Vec<String>,
    }

    impl Keyword {
        #[allow(unused)]
        pub fn filter(&self) -> &Vec<String> {
            &self.filter
        }
        pub fn accepted(&self) -> &Vec<String> {
            &self.accepted
        }
    }
}

/*mod test_url {
    use super::{Deserialize, Serialize};

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct TestUrl {
        proxy: String,
        url: String,
    }

    impl TestUrl {
        pub fn proxy(&self) -> &str {
            &self.proxy
        }
        pub fn url(&self) -> &str {
            &self.url
        }
    }
}*/

mod http_configure {

    use super::Deserialize;
    //use std::collections::HashMap;

    const DEFAULT_REDIS_SERVER: &str = "redis://127.0.0.1/";

    fn get_default_redis_server() -> String {
        DEFAULT_REDIS_SERVER.to_string()
    }

    #[derive(Clone, Debug, Deserialize)]
    pub struct HttpServerConfigure {
        address: String,
        port: u16,
        #[serde(default = "get_default_redis_server")]
        redis_address: String,
    }

    impl HttpServerConfigure {
        pub fn address(&self) -> &str {
            &self.address
        }
        pub fn port(&self) -> u16 {
            self.port
        }
        pub fn redis_address(&self) -> &str {
            &self.redis_address
        }
    }

    impl Default for HttpServerConfigure {
        fn default() -> Self {
            Self {
                address: "127.0.0.1".to_string(),
                port: 23365,
                redis_address: DEFAULT_REDIS_SERVER.to_string(),
            }
        }
    }
}

mod upstream {

    use super::Deserialize;
    //use std::collections::HashMap;

    #[derive(Clone, Debug, Deserialize)]
    pub struct UpStream {
        sub_id: String,
        upstream: String,
        raw: Option<String>,
    }

    impl UpStream {
        pub fn sub_id(&self) -> &str {
            &self.sub_id
        }
        pub fn upstream(&self) -> &str {
            &self.upstream
        }
        pub fn raw(&self) -> Option<&String> {
            self.raw.as_ref()
        }
    }
}

mod configure {
    use super::Deserialize;
    use super::{HttpServerConfigure, Keyword, Proxies, Rules, UpStream};
    //use std::collections::HashMap;

    pub fn default_test_url() -> String {
        "http://www.gstatic.com/generate_204".to_string()
    }

    #[derive(Clone, Debug, Deserialize)]
    pub struct Configure {
        upstream: Vec<UpStream>,
        rules: Rules,
        proxies: Proxies,
        keyword: Keyword,
        #[serde(default = "default_test_url")]
        test_url: String,
        #[serde(default)]
        http: HttpServerConfigure,
        #[serde(default)]
        manual_add_group_name: Vec<String>,
    }

    impl Configure {
        pub fn rules(&self) -> &Rules {
            &self.rules
        }
        pub fn proxies(&self) -> &Proxies {
            &self.proxies
        }
        pub fn keyword(&self) -> &Keyword {
            &self.keyword
        }
        /*pub fn get_url_maps(&self) -> HashMap<String, String> {
            let mut m = HashMap::new();
            if let Some(&test_urls) = self.test_urls {
                for test_url in test_urls {
                    m.insert(test_url.proxy().to_string(), test_url.url().to_string());
                }
            }
            m
        }*/
        pub fn test_url(&self) -> String {
            self.test_url.clone()
        }
        pub fn upstream(&self) -> &Vec<UpStream> {
            &self.upstream
        }
        pub fn http(&self) -> &HttpServerConfigure {
            &self.http
        }

        pub fn need_added_proxy(self) -> Vec<String> {
            self.manual_add_group_name
        }
    }
}

mod share_config {
    use super::{Keyword, Proxies, Rules};
    use crate::parser::{Configure, UpStream};
    use log::{debug, error, info};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tap::TapFallible;
    use tokio::sync::RwLock;

    #[derive(Clone, Debug)]
    pub enum UpdateConfigureEvent {
        NeedUpdate,
        Terminate,
    }

    pub struct UrlConfig {
        upstream: String,
        raw: Option<String>,
    }

    impl UrlConfig {
        pub fn upstream(&self) -> &str {
            &self.upstream
        }
        pub fn raw(&self) -> Option<&String> {
            self.raw.as_ref()
        }
        pub fn new(upstream: String, raw: Option<String>) -> Self {
            Self { upstream, raw }
        }
    }

    impl From<&UpStream> for UrlConfig {
        fn from(value: &UpStream) -> Self {
            Self::new(value.upstream().to_string(), value.raw().cloned())
        }
    }

    pub struct ShareConfig {
        redis_client: redis::Client,
        upstream: HashMap<String, UrlConfig>,
        rules: Rules,
        proxies: Proxies,
        keyword: Keyword,
        test_url: String,
        manual_insert_proxies: Vec<String>,
    }

    impl ShareConfig {
        pub async fn get_redis_connection(&self) -> anyhow::Result<redis::aio::Connection> {
            Ok(self.redis_client.get_async_connection().await?)
        }
        pub fn search_url(&self, key: &str) -> Option<&UrlConfig> {
            self.upstream.get(key)
        }
        pub fn new(local_configure: Configure, redis_client: redis::Client) -> Self {
            Self {
                upstream: Self::upstreams_into_hashmap(local_configure.upstream()),
                rules: local_configure.rules().clone(),
                proxies: local_configure.proxies().clone(),
                keyword: local_configure.keyword().clone(),
                redis_client,
                test_url: local_configure.test_url(),
                manual_insert_proxies: local_configure.need_added_proxy(),
            }
        }
        pub fn rules(&self) -> &Rules {
            &self.rules
        }
        pub fn proxies(&self) -> &Proxies {
            &self.proxies
        }
        #[allow(unused)]
        pub fn keyword(&self) -> &Keyword {
            &self.keyword
        }
        /*pub fn test_url(&self) -> String {
            self.test_url.clone()
        }*/
        pub fn upstreams_into_hashmap(v: &Vec<UpStream>) -> HashMap<String, UrlConfig> {
            let mut m = HashMap::new();
            for map in v {
                m.insert(map.sub_id().to_string(), UrlConfig::from(map));
            }
            debug!("Find {} subscriptions", m.len());
            m
        }
        pub fn update(&mut self, local_configure: Configure) {
            self.upstream = Self::upstreams_into_hashmap(local_configure.upstream());
            self.rules = local_configure.rules().clone();
            self.keyword = local_configure.keyword().clone();
            self.proxies = local_configure.proxies().clone();
            self.test_url = local_configure.test_url();
            self.manual_insert_proxies = local_configure.need_added_proxy();
        }

        pub async fn configure_file_updater(
            configure_path: String,
            configure_file: Arc<RwLock<ShareConfig>>,
            mut receiver: tokio::sync::mpsc::Receiver<UpdateConfigureEvent>,
        ) {
            while let Some(event) = receiver.recv().await {
                match event {
                    UpdateConfigureEvent::NeedUpdate => {
                        let mut cfg = configure_file.write().await;
                        if let Some(new_cfg) = tokio::fs::read_to_string(&configure_path)
                            .await
                            .tap_err(|e| {
                                error!(
                                    "[Can be safely ignored] Unable to read configure file: {:?}",
                                    e
                                )
                            })
                            .ok()
                            .and_then(|s| {
                                serde_yaml::from_str::<Configure>(s.as_str())
                                    .tap_err(|e| {
                                        error!(
                                    "[Can be safely ignored] Unable to parse local configure: {:?}",
                                    e
                                )
                                    })
                                    .ok()
                            })
                        {
                            cfg.update(new_cfg);
                            info!("Reloaded local configure file.");
                        };
                    }
                    UpdateConfigureEvent::Terminate => break,
                }
            }
            debug!("File updater exited!");
        }
        pub fn manual_insert_proxies(&self) -> &Vec<String> {
            &self.manual_insert_proxies
        }
    }
}

use serde_derive::{Deserialize, Serialize};

pub use configure::Configure;
pub use http_configure::HttpServerConfigure;
pub use keyword::Keyword;
pub use proxies::{Proxies, Proxy};
pub use proxy_groups::{ProxyGroup, ProxyGroups};
pub use remote_configure::RemoteConfigure;
pub use rules::Rules;
pub use share_config::{ShareConfig, UpdateConfigureEvent};
pub use upstream::UpStream;
