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
        pub fn name(&self) -> &str {
            &self.name
        }
        pub fn proxy_type(&self) -> &str {
            &self.type_
        }
        pub fn server(&self) -> &str {
            &self.server
        }
        pub fn port(&self) -> u16 {
            self.port
        }
        pub fn cipher(&self) -> &str {
            &self.cipher
        }
        pub fn password(&self) -> &str {
            &self.password
        }
        pub fn udp(&self) -> bool {
            self.udp
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct Proxies(pub Vec<Proxy>);

    impl Proxies {
        fn insert_head(&mut self, mut from: Vec<Proxy>) -> &mut Self {
            from.extend(self.0.iter().map(|s| s.clone()));
            self.0 = from;
            self
        }
    }
}

mod proxy_groups {

    use super::{Deserialize, Serialize};

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct ProxyGroup {
        name: String,
        #[serde(rename = "type")]
        type_: String,
        proxies: Vec<String>,
    }

    impl ProxyGroup {
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
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct ProxyGroups(pub Vec<ProxyGroup>);
}

mod rules {

    use super::{Deserialize, Serialize};

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct Rules(Vec<String>);

    impl Rules {
        fn insert_head(&mut self, mut from: Vec<String>) -> &mut Self {
            from.extend(self.0.iter().map(|s| s.clone()));
            self.0 = from;
            self
        }
    }
}
mod configure {
    use super::{Proxies, ProxyGroups, Rules};
    use log::{info, warn};

    use super::{Deserialize, Serialize};

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct Configure {
        #[serde(rename = "proxy-groups")]
        proxy_groups: ProxyGroups,
        rules: Rules,
        proxies: Proxies,
        port: u16,
        #[serde(rename = "socks-port")]
        socks_port: u16,
        #[serde(rename = "redir-port")]
        redir_port: u16,
        #[serde(rename = "allow-lan")]
        allow_lan: bool,
        mode: String,
        #[serde(rename = "log-level")]
        log_level: String,
        #[serde(rename = "external-controller")]
        external_controller: String,
        secret: String,
    }

    impl Configure {
        pub fn proxy_groups(&self) -> &ProxyGroups {
            &self.proxy_groups
        }
        pub fn rules(&self) -> &Rules {
            &self.rules
        }
        pub fn proxies(&self) -> &Proxies {
            &self.proxies
        }

        pub fn optimize(&mut self) -> &mut Self {
            let mut v = vec![];
            for element in &self.proxies.0 {
                if element.password().is_empty() {
                    v.push(element.name())
                }
            }
            for element in &mut self.proxy_groups.0 {
                for item in &v {
                    let ret = element.proxies().iter().position(|x| x.eq(item));
                    if let None = ret {
                        warn!("Not found: {:?}", item);
                        continue;
                    }
                    element.remove(ret.unwrap());
                }
            }
            info!("Remove {} empty password elements.", v.len());
            self
        }
    }
}

use serde_derive::{Deserialize, Serialize};

pub use configure::Configure as RemoteConfigure;
pub use proxies::{Proxies, Proxy};
pub use proxy_groups::{ProxyGroup, ProxyGroups};
pub use rules::Rules;
