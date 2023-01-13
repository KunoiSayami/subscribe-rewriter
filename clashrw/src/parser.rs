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
        pub fn insert_head(&mut self, mut from: Vec<Proxy>) -> &mut Self {
            from.extend(self.0.iter().map(|s| s.clone()));
            self.0 = from;
            self
        }

        pub fn get_element(&self) -> Vec<Proxy> {
            self.0.clone()
        }

        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn get_vec(&self) -> &Vec<Proxy> {
            &self.0
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

        pub fn new_relay(first: String, second: String) -> Self {
            Self {
                name: format!("{} {}", first, second),
                type_: "relay".to_string(),
                proxies: vec![first, second],
            }
        }
        pub fn set_proxies(&mut self, proxies: Vec<String>) {
            self.proxies = proxies;
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
        fn insert_head(&mut self, mut from: Vec<String>) -> &mut Self {
            from.extend(self.0.iter().map(|s| s.clone()));
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
    use log::info;

    use super::{Deserialize, Serialize};

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct RemoteConfigure {
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
        pub fn rules(&self) -> &Rules {
            &self.rules
        }
        pub fn proxies(&self) -> &Proxies {
            &self.proxies
        }
        pub fn mut_proxies(&mut self) -> &mut Proxies {
            &mut self.proxies
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
}

mod keyword {
    use super::{Deserialize, Serialize};

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct Keyword {
        filter: Vec<String>,
        accepted: Vec<String>,
    }

    impl Keyword {
        pub fn filter(&self) -> &Vec<String> {
            &self.filter
        }
        pub fn accepted(&self) -> &Vec<String> {
            &self.accepted
        }
    }
}

mod configure {
    use super::{Deserialize, Serialize};
    use super::{Keyword, Proxies, Rules};

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct Configure {
        rules: Rules,
        proxies: Proxies,
        keyword: Keyword,
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
    }
}

use serde_derive::{Deserialize, Serialize};

pub use configure::Configure;
pub use keyword::Keyword;
pub use proxies::{Proxies, Proxy};
pub use proxy_groups::{ProxyGroup, ProxyGroups};
pub use remote_configure::RemoteConfigure;
pub use rules::Rules;
