use std::sync::Arc;

use pretty_assertions::assert_eq;

use super::*;

struct RuntimeResetGuard {
    previous: Option<Arc<NetworkRuntime>>,
}

impl RuntimeResetGuard {
    fn clear() -> Self {
        let mut guard = NETWORK_RUNTIME
            .write()
            .expect("network runtime lock should not be poisoned");
        Self {
            previous: guard.take(),
        }
    }
}

impl Drop for RuntimeResetGuard {
    fn drop(&mut self) {
        let mut guard = NETWORK_RUNTIME
            .write()
            .expect("network runtime lock should not be poisoned");
        *guard = self.previous.take();
    }
}

#[tokio::test]
async fn apply_doh_resolver_initializes_default_runtime() {
    let _reset = RuntimeResetGuard::clear();

    assert!(configured_runtime().is_none());
    assert_eq!(
        resolve_host_with_doh("localhost", 443).await.unwrap(),
        vec![
            SocketAddr::from(([127, 0, 0, 1], 443)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 443)),
        ],
    );
    assert!(configured_runtime().is_none());

    apply_doh_resolver(reqwest::Client::builder())
        .expect("DoH resolver should initialize default networking runtime");

    let runtime = configured_runtime()
        .expect("networking runtime should be configured after applying DoH resolver");
    assert_eq!(
        runtime.resolve_host_ips("localhost.").await.unwrap(),
        vec![
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ],
    );
    assert_eq!(
        runtime
            .doh_servers
            .iter()
            .map(reqwest::Url::to_string)
            .collect::<Vec<_>>(),
        default_doh_servers(),
    );
}
