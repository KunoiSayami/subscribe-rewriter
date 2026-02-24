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
        #[serde(rename = "dialer-proxy", skip_serializing_if = "Option::is_none")]
        dialer_proxy: Option<String>,
        udp: bool,
    }

    impl Proxy {
        pub fn password(&self) -> &str {
            &self.password
        }

        pub fn replace_dialer_proxy(value: &mut serde_yaml::Value, target: &str) {
            let has_placeholder = value["dialer-proxy"]
                .as_str()
                .is_some_and(|v| v.eq("<PlaceHold>"));

            if has_placeholder {
                value["dialer-proxy"] = target.into();
            }
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

        pub(crate) fn len(&self) -> usize {
            self.0.len()
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
        #[serde(skip_serializing, default)]
        apply_to: Vec<String>,
        #[serde(skip_serializing, default)]
        not_apply_to: Vec<String>,
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
                type_: "select".into(),
                proxies,
                ..Default::default()
            }
        }

        #[allow(unused)]
        pub fn new_url_test(name: String, proxies: Vec<String>, url: String) -> Self {
            Self {
                name,
                type_: "url-test".into(),
                proxies,
                url: Some(url),
                interval: Some(600),
                apply_to: vec![],
                not_apply_to: vec![],
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
            self.proxies.push(DIRECT_NAME.into());
            self
        }

        pub fn proxies_mut(&mut self) -> &mut Vec<String> {
            &mut self.proxies
        }

        pub fn apply_to(&self) -> &[String] {
            &self.apply_to
        }

        pub fn not_apply_to(&self) -> &[String] {
            &self.not_apply_to
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize, Default)]
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

        pub(crate) fn len(&self) -> usize {
            self.0.len()
        }

        pub(super) fn append(&mut self, mut from: Vec<String>) -> &mut Self {
            self.0.append(&mut from);
            self
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
            let v = self
                .proxies
                .0
                .iter()
                .filter_map(|x| Proxy::is_empty_password(x.clone()))
                .collect::<Vec<_>>();

            /* for element in &self.proxies.0 {
                if let Some(name) = Proxy::is_empty_password(element.clone()) {
                    v.push(name);
                }
            } */
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

        pub fn proxies_len(&self) -> usize {
            self.proxies.0.len()
        }

        pub(crate) fn normalize(&mut self) {
            self.mode = self.mode.to_ascii_lowercase();
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
                address: "127.0.0.1".into(),
                port: 23365,
                redis_address: DEFAULT_REDIS_SERVER.into(),
            }
        }
    }
}

mod upstream {
    use super::Deserialize;
    use crate::parser::share_config::OverridableValue;
    //use std::collections::HashMap;

    #[derive(Clone, Debug, Deserialize)]
    pub struct UpStream {
        sub_id: String,
        upstream: String,
        raw: Option<String>,
        #[serde(rename = "override")]
        sub_override: Option<OverridableValue>,
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

        pub fn sub_override(&self) -> Option<OverridableValue> {
            self.sub_override
        }
    }
}

mod configure {
    use std::path::Path;

    use crate::parser::ProxyGroup;
    use crate::parser::external_config::ExternalConfig;

    use anyhow::Context;

    use super::Deserialize;
    use super::{HttpServerConfigure, Keyword, Proxies, Rules, UpStream};
    //use std::collections::HashMap;

    fn default_test_url() -> String {
        "http://www.gstatic.com/generate_204".into()
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
        #[serde(default, alias = "groups", alias = "proxy-groups")]
        proxy_groups: Vec<ProxyGroup>,
        #[serde(default, alias = "additional-rules")]
        additional_rules: Vec<String>,
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

        pub fn proxy_groups(&self) -> &Vec<ProxyGroup> {
            &self.proxy_groups
        }

        pub(crate) async fn load<P: AsRef<Path>>(p: P) -> anyhow::Result<Self> {
            let mut ret = serde_yaml::from_str::<Self>(
                tokio::fs::read_to_string(p.as_ref())
                    .await
                    .context("read local config")?
                    .as_str(),
            )
            .context("Parse configure")?;

            let mut rules_count = 0;

            for (path, target) in ret
                .additional_rules
                .iter()
                .filter_map(|x| x.split_once(','))
            {
                let Ok(ext) = ExternalConfig::load(path)
                    .await
                    .inspect_err(|e| log::warn!("Load external config {path}: {e:?}"))
                else {
                    continue;
                };

                let t = ext.transform(target);
                rules_count += t.len();

                ret.rules.append(t);
            }

            if ret.additional_rules.len() > 0 {
                log::debug!("Load {rules_count} from external configure");
            }
            Ok(ret)
        }
    }
}

mod external_config {
    use std::path::Path;

    use anyhow::Context;
    use serde::Deserialize;

    macro_rules! insert_domain {
        ($head: literal, $array: expr, $t: tt, $v:tt) => {
            for domain in &$array {
                $v.push(format!("{}, {}, {}", $head, domain, $t));
            }
        };
    }

    #[derive(Clone, Debug, Deserialize)]
    pub struct ExternalConfigSub {
        domain: Vec<String>,
        domain_suffix: Vec<String>,
        domain_regex: Vec<String>,
    }

    impl ExternalConfigSub {
        pub(crate) fn transform(&self, target: &str) -> Vec<String> {
            let mut ret = Vec::with_capacity(
                self.domain.len() + self.domain_suffix.len() + self.domain_regex.len(),
            );

            insert_domain!("DOMAIN", self.domain, target, ret);
            insert_domain!("DOMAIN-SUFFIX", self.domain_suffix, target, ret);
            insert_domain!("DOMAIN-REGEX", self.domain_regex, target, ret);
            ret
        }
    }

    #[derive(Clone, Debug, Deserialize)]
    pub struct ExternalConfig {
        rules: Vec<ExternalConfigSub>,
    }

    impl ExternalConfig {
        pub(crate) async fn load<P: AsRef<Path>>(p: P) -> anyhow::Result<Self> {
            serde_json::from_str(
                tokio::fs::read_to_string(p.as_ref())
                    .await
                    .context("read external config")?
                    .as_str(),
            )
            .context("parse external config")
        }

        pub(crate) fn transform(self, target: &str) -> Vec<String> {
            self.rules
                .iter()
                .map(|x| x.transform(target))
                .flatten()
                .collect()
        }
    }
}

mod share_config {
    use super::{Keyword, Proxies, Rules};
    use crate::parser::{Configure, ProxyGroup, UpStream};
    use log::{debug, error, info};
    use serde::Deserialize;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[derive(Clone, Debug)]
    pub enum UpdateConfigureEvent {
        NeedUpdate,
        Terminate,
    }

    #[derive(Clone, Copy, Debug, Deserialize)]
    pub struct OverridableValue {
        expire: Option<u64>,
        total: Option<u64>,
        download: Option<u64>,
        upload: Option<u64>,
    }

    impl OverridableValue {
        pub fn rewrite(&self, input: String) -> String {
            if input.is_empty() {
                return input;
            }
            if input.contains(';') {
                let mut v = Vec::new();
                for slice in input.split(';').map(|s| s.trim()) {
                    if !slice.contains("=") {
                        v.push(slice.to_string());
                        continue;
                    }
                    let (key, value) = slice.split_once('=').unwrap();
                    v.push(match key {
                        "upload" => Self::check_and_push(key, self.upload, value),
                        "download" => Self::check_and_push(key, self.download, value),
                        "total" => Self::check_and_push(key, self.total, value),
                        "expire" => Self::check_and_push(key, self.expire, value),
                        _ => slice.to_string(),
                    });
                }
                return v.join(";");
            }
            input
        }

        fn check_and_push(key: &str, value: Option<u64>, origin: &str) -> String {
            format!(
                "{}={}",
                key,
                if let Some(value) = value {
                    value.to_string()
                } else {
                    origin.to_string()
                }
            )
        }
    }

    #[derive(Clone, Debug)]
    pub struct UrlConfig {
        upstream: String,
        raw: Option<String>,
        sub_override: Option<OverridableValue>,
    }

    impl UrlConfig {
        pub fn upstream(&self) -> &str {
            &self.upstream
        }
        pub fn raw(&self) -> Option<&str> {
            self.raw.as_deref()
        }
        pub fn new(
            upstream: String,
            raw: Option<String>,
            sub_override: Option<OverridableValue>,
        ) -> Self {
            Self {
                upstream,
                raw,
                sub_override,
            }
        }
        pub fn sub_override(&self) -> Option<OverridableValue> {
            self.sub_override
        }
    }

    impl From<&UpStream> for UrlConfig {
        fn from(value: &UpStream) -> Self {
            Self::new(
                value.upstream().to_string(),
                value.raw().cloned(),
                value.sub_override(),
            )
        }
    }

    pub struct ShareConfig {
        redis_client: redis::Client,
        upstream: HashMap<String, UrlConfig>,
        rules: Rules,
        proxies: Proxies,
        groups: Vec<ProxyGroup>,
        keyword: Keyword,
        test_url: String,
        manual_insert_proxies: Vec<String>,
    }

    impl ShareConfig {
        pub async fn get_redis_connection(
            &self,
        ) -> anyhow::Result<redis::aio::MultiplexedConnection> {
            Ok(self.redis_client.get_multiplexed_async_connection().await?)
        }
        pub fn search_url(&self, key: &str) -> Option<&UrlConfig> {
            self.upstream.get(key)
        }
        pub fn new(local_configure: Configure, redis_client: redis::Client) -> Self {
            let ret = Self {
                upstream: Self::upstreams_into_hashmap(local_configure.upstream()),
                rules: local_configure.rules().clone(),
                proxies: local_configure.proxies().clone(),
                keyword: local_configure.keyword().clone(),
                redis_client,
                groups: local_configure.proxy_groups().clone(),
                test_url: local_configure.test_url(),
                manual_insert_proxies: local_configure.need_added_proxy(),
            };
            log::debug!("{}", ret.briefing());
            ret
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
            v.into_iter()
                .map(|x| (x.sub_id().to_string(), UrlConfig::from(x)))
                .collect()
        }

        pub fn update(&mut self, local_configure: Configure) {
            self.upstream = Self::upstreams_into_hashmap(local_configure.upstream());
            self.rules = local_configure.rules().clone();
            self.keyword = local_configure.keyword().clone();
            self.proxies = local_configure.proxies().clone();
            self.groups = local_configure.proxy_groups().clone();
            self.test_url = local_configure.test_url();
            self.manual_insert_proxies = local_configure.need_added_proxy();
            log::debug!("{}", self.briefing());
        }

        pub fn briefing(&self) -> String {
            format!(
                "Find {} subscriptions, {} rules, {} proxies, {} groups",
                self.upstream.len(),
                self.rules.len(),
                self.proxies.len(),
                self.groups.len(),
            )
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
                        if let Some(new_cfg) = Configure::load(&configure_path)
                            .await
                            .inspect_err(|e| {
                                error!("[Can be safely ignored] Load configure: {e:?}")
                            })
                            .ok()
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

        pub fn groups(&self) -> &Vec<ProxyGroup> {
            &self.groups
        }
    }
}

use serde::{Deserialize, Serialize};

pub use configure::Configure;
pub use http_configure::HttpServerConfigure;
pub use keyword::Keyword;
pub use proxies::{Proxies, Proxy};
pub use proxy_groups::{ProxyGroup, ProxyGroups};
pub use remote_configure::RemoteConfigure;
pub use rules::Rules;
pub use share_config::{ShareConfig, UpdateConfigureEvent};
pub use upstream::UpStream;

#[cfg(test)]
mod tests {
    use super::Proxy;

    fn make_proxy_value(dialer_proxy: Option<&str>) -> serde_yaml::Value {
        let mut yaml = format!(
            "name: test\ntype: ss\nserver: 1.2.3.4\nport: 443\ncipher: aes-256-gcm\npassword: pass\nudp: true\n"
        );
        if let Some(dp) = dialer_proxy {
            yaml.push_str(&format!("dialer-proxy: {dp}\n"));
        }
        serde_yaml::from_str(&yaml).unwrap()
    }

    fn get_dialer_proxy(value: &serde_yaml::Value) -> Option<String> {
        value
            .as_mapping()
            .and_then(|m| m.get(&serde_yaml::Value::String("dialer-proxy".into())))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    #[test]
    fn replace_dialer_proxy_with_placeholder() {
        let mut value = make_proxy_value(Some("<PlaceHold>"));
        Proxy::replace_dialer_proxy(&mut value, "my-proxy");
        assert_eq!(get_dialer_proxy(&value).as_deref(), Some("my-proxy"));
    }

    #[test]
    fn replace_dialer_proxy_skips_different_value() {
        let mut value = make_proxy_value(Some("other-proxy"));
        Proxy::replace_dialer_proxy(&mut value, "my-proxy");
        assert_eq!(get_dialer_proxy(&value).as_deref(), Some("other-proxy"));
    }

    #[test]
    fn replace_dialer_proxy_skips_when_absent() {
        let mut value = make_proxy_value(None);
        Proxy::replace_dialer_proxy(&mut value, "my-proxy");
        assert_eq!(get_dialer_proxy(&value), None);
    }
}
