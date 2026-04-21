use crate::BuildCustomCaTransportError;
use crate::custom_ca::build_reqwest_client_with_custom_ca_without_doh;
use reqwest::dns::Addrs;
use reqwest::dns::Name;
use reqwest::dns::Resolve;
use reqwest::dns::Resolving;
use serde::Deserialize;
use serde::Serialize;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::RwLock;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkRuntimeConfig {
    pub doh_servers: Vec<String>,
    pub request_log_path: Option<PathBuf>,
}

#[derive(Debug, Error)]
pub enum NetworkRuntimeConfigError {
    #[error("networking.doh_servers must contain at least one URL")]
    EmptyDohServers,
    #[error("invalid DoH URL `{url}`: {detail}")]
    InvalidDohUrl { url: String, detail: String },
    #[error("DoH URL `{url}` must use http or https")]
    InvalidDohScheme { url: String },
    #[error("DoH URL `{url}` must include a host")]
    MissingDohHost { url: String },
    #[error("DoH URL `{url}` must use an IP-literal host to avoid system DNS bootstrap")]
    DohHostMustBeIpLiteral { url: String },
    #[error("failed to build DoH HTTP client: {source}")]
    BuildDohClient {
        #[source]
        source: BuildCustomCaTransportError,
    },
    #[error("failed to open request log file `{path}`: {source}")]
    OpenRequestLogFile {
        path: PathBuf,
        source: io::Error,
    },
    #[error("networking runtime lock is poisoned")]
    RuntimeLockPoisoned,
}

#[derive(Debug)]
struct NetworkRuntime {
    doh_servers: Vec<reqwest::Url>,
    doh_http_client: reqwest::Client,
    request_logger: Option<RequestMetadataLogger>,
}

#[derive(Clone, Debug)]
struct RequestMetadataLogger {
    file: Arc<Mutex<File>>,
}

#[derive(Debug, Serialize)]
struct RequestMetadataRecord<'a> {
    ts: i128,
    transport: &'a str,
    method: &'a str,
    url: &'a str,
    status: Option<u16>,
    duration_ms: u128,
    error: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct DohJsonResponse {
    #[serde(rename = "Status")]
    status: i32,
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohJsonAnswer>>,
}

#[derive(Debug, Deserialize)]
struct DohJsonAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    data: String,
}

#[derive(Debug, Clone, Copy)]
enum DohRecordType {
    A,
    Aaaa,
}

impl DohRecordType {
    fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
        }
    }

    fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }
}

static NETWORK_RUNTIME: LazyLock<RwLock<Option<Arc<NetworkRuntime>>>> =
    LazyLock::new(|| RwLock::new(None));

pub fn default_doh_servers() -> Vec<String> {
    [
        "https://1.1.1.1/dns-query",
        "https://1.0.0.1/dns-query",
        "https://8.8.8.8/resolve",
    ]
    .into_iter()
    .map(ToString::to_string)
    .collect()
}

pub fn configure_networking(config: NetworkRuntimeConfig) -> Result<(), NetworkRuntimeConfigError> {
    let runtime = Arc::new(build_network_runtime(config)?);

    let mut guard = NETWORK_RUNTIME
        .write()
        .map_err(|_| NetworkRuntimeConfigError::RuntimeLockPoisoned)?;
    *guard = Some(runtime);
    Ok(())
}

pub fn ensure_networking_configured_with_defaults() -> Result<(), NetworkRuntimeConfigError> {
    if configured_runtime().is_some() {
        return Ok(());
    }

    let runtime = Arc::new(build_network_runtime(NetworkRuntimeConfig {
        doh_servers: default_doh_servers(),
        request_log_path: None,
    })?);

    let mut guard = NETWORK_RUNTIME
        .write()
        .map_err(|_| NetworkRuntimeConfigError::RuntimeLockPoisoned)?;
    if guard.is_none() {
        *guard = Some(runtime);
    }
    Ok(())
}

pub fn log_request_metadata(
    transport: &str,
    method: &str,
    url: &str,
    status: Option<u16>,
    duration: Duration,
    error: Option<&str>,
) {
    let Some(runtime) = configured_runtime() else {
        return;
    };
    let Some(logger) = runtime.request_logger.as_ref() else {
        return;
    };

    let record = RequestMetadataRecord {
        ts: unix_timestamp_millis(),
        transport,
        method,
        url,
        status,
        duration_ms: duration.as_millis(),
        error,
    };
    logger.write_record(&record);
}

pub async fn resolve_host_with_doh(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    ensure_networking_configured_with_defaults().map_err(io::Error::other)?;
    let Some(runtime) = configured_runtime() else {
        return Err(io::Error::other(
            "networking runtime should be configured after default initialization",
        ));
    };
    let ips = runtime.resolve_host_ips(host).await?;
    if ips.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no DNS records found for {host}"),
        ));
    }
    Ok(ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

pub(crate) fn apply_doh_resolver(
    builder: reqwest::ClientBuilder,
) -> Result<reqwest::ClientBuilder, String> {
    ensure_networking_configured_with_defaults().map_err(|error| error.to_string())?;
    let Some(runtime) = configured_runtime() else {
        return Err("networking runtime is not configured".to_string());
    };
    Ok(builder.dns_resolver(Arc::new(DohReqwestResolver { runtime })))
}

pub fn apply_doh_resolver_blocking(
    builder: reqwest::blocking::ClientBuilder,
) -> Result<reqwest::blocking::ClientBuilder, String> {
    ensure_networking_configured_with_defaults().map_err(|error| error.to_string())?;
    let Some(runtime) = configured_runtime() else {
        return Err("networking runtime is not configured".to_string());
    };
    Ok(builder.dns_resolver(Arc::new(DohReqwestResolver { runtime })))
}

fn configured_runtime() -> Option<Arc<NetworkRuntime>> {
    NETWORK_RUNTIME
        .read()
        .ok()
        .and_then(|guard| guard.as_ref().cloned())
}

fn build_network_runtime(
    config: NetworkRuntimeConfig,
) -> Result<NetworkRuntime, NetworkRuntimeConfigError> {
    if config.doh_servers.is_empty() {
        return Err(NetworkRuntimeConfigError::EmptyDohServers);
    }

    let doh_servers = config
        .doh_servers
        .iter()
        .map(|value| validate_doh_server(value))
        .collect::<Result<Vec<_>, _>>()?;

    let doh_http_client =
        build_reqwest_client_with_custom_ca_without_doh(reqwest::Client::builder().no_proxy())
            .map_err(|source| NetworkRuntimeConfigError::BuildDohClient { source })?;

    let request_logger = config
        .request_log_path
        .as_ref()
        .map(RequestMetadataLogger::new)
        .transpose()?;

    Ok(NetworkRuntime {
        doh_servers,
        doh_http_client,
        request_logger,
    })
}

impl NetworkRuntime {
    async fn resolve_host_ips(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        let mut last_error = None;
        for server in &self.doh_servers {
            match self.resolve_host_ips_with_server(server, host).await {
                Ok(ips) => return Ok(ips),
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            }
        }

        let detail = last_error.unwrap_or_else(|| "all DoH servers failed".to_string());
        Err(io::Error::other(format!(
            "failed to resolve {host} via DoH: {detail}"
        )))
    }

    async fn resolve_host_ips_with_server(
        &self,
        server: &reqwest::Url,
        host: &str,
    ) -> Result<Vec<IpAddr>, String> {
        let a_records = self
            .query_doh(server, host, DohRecordType::A)
            .await
            .unwrap_or_default();
        let aaaa_records = self
            .query_doh(server, host, DohRecordType::Aaaa)
            .await
            .unwrap_or_default();

        let mut combined = Vec::with_capacity(a_records.len() + aaaa_records.len());
        combined.extend(a_records);
        combined.extend(aaaa_records);
        if combined.is_empty() {
            return Err(format!("server {server} returned no address records"));
        }
        combined.sort_unstable();
        combined.dedup();
        Ok(combined)
    }

    async fn query_doh(
        &self,
        server: &reqwest::Url,
        host: &str,
        record_type: DohRecordType,
    ) -> Result<Vec<IpAddr>, String> {
        let mut url = server.clone();
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("name", host);
            pairs.append_pair("type", record_type.as_str());
        }

        let start = Instant::now();
        let response = self
            .doh_http_client
            .get(url.clone())
            .header("accept", "application/dns-json")
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                let message = error.to_string();
                log_request_metadata(
                    "doh",
                    "GET",
                    url.as_str(),
                    None,
                    start.elapsed(),
                    Some(message.as_str()),
                );
                return Err(message);
            }
        };

        let status = response.status();
        let parsed = response.json::<DohJsonResponse>().await;
        let duration = start.elapsed();
        match parsed {
            Ok(payload) => {
                if !status.is_success() {
                    let message = format!("HTTP {status}");
                    log_request_metadata(
                        "doh",
                        "GET",
                        url.as_str(),
                        Some(status.as_u16()),
                        duration,
                        Some(message.as_str()),
                    );
                    return Err(message);
                }
                if payload.status != 0 {
                    let message = format!("DNS status {}", payload.status);
                    log_request_metadata(
                        "doh",
                        "GET",
                        url.as_str(),
                        Some(status.as_u16()),
                        duration,
                        Some(message.as_str()),
                    );
                    return Err(message);
                }

                let mut ips = Vec::new();
                if let Some(answer) = payload.answer {
                    for record in answer {
                        if record.record_type != record_type.code() {
                            continue;
                        }
                        if let Ok(ip) = record.data.parse::<IpAddr>() {
                            ips.push(ip);
                        }
                    }
                }

                log_request_metadata(
                    "doh",
                    "GET",
                    url.as_str(),
                    Some(status.as_u16()),
                    duration,
                    None,
                );
                Ok(ips)
            }
            Err(error) => {
                let message = error.to_string();
                log_request_metadata(
                    "doh",
                    "GET",
                    url.as_str(),
                    Some(status.as_u16()),
                    duration,
                    Some(message.as_str()),
                );
                Err(message)
            }
        }
    }
}

impl RequestMetadataLogger {
    fn new(path: &PathBuf) -> Result<Self, NetworkRuntimeConfigError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|source| NetworkRuntimeConfigError::OpenRequestLogFile {
                path: path.clone(),
                source,
            })?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }

    fn write_record(&self, record: &RequestMetadataRecord<'_>) {
        let Ok(json) = serde_json::to_string(record) else {
            return;
        };
        let Ok(mut guard) = self.file.lock() else {
            return;
        };
        let _ = writeln!(guard, "{json}");
    }
}

#[derive(Debug)]
struct DohReqwestResolver {
    runtime: Arc<NetworkRuntime>,
}

impl Resolve for DohReqwestResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let runtime = Arc::clone(&self.runtime);
        let host = name.as_str().to_string();
        Box::pin(async move {
            let ips = runtime.resolve_host_ips(&host).await?;
            let addrs: Addrs = Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

fn validate_doh_server(value: &str) -> Result<reqwest::Url, NetworkRuntimeConfigError> {
    let url = reqwest::Url::parse(value).map_err(|error| NetworkRuntimeConfigError::InvalidDohUrl {
        url: value.to_string(),
        detail: error.to_string(),
    })?;

    if !matches!(url.scheme(), "http" | "https") {
        return Err(NetworkRuntimeConfigError::InvalidDohScheme {
            url: value.to_string(),
        });
    }

    let Some(host) = url.host_str() else {
        return Err(NetworkRuntimeConfigError::MissingDohHost {
            url: value.to_string(),
        });
    };
    if host.parse::<IpAddr>().is_err() {
        return Err(NetworkRuntimeConfigError::DohHostMustBeIpLiteral {
            url: value.to_string(),
        });
    }
    Ok(url)
}

fn unix_timestamp_millis() -> i128 {
    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    i128::from(duration.as_secs()) * 1000 + i128::from(duration.subsec_millis())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

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

    #[test]
    fn default_doh_servers_match_expected_values() {
        assert_eq!(
            default_doh_servers(),
            vec![
                "https://1.1.1.1/dns-query".to_string(),
                "https://1.0.0.1/dns-query".to_string(),
                "https://8.8.8.8/resolve".to_string(),
            ]
        );
    }

    #[test]
    fn apply_doh_resolver_initializes_default_runtime() {
        let _reset = RuntimeResetGuard::clear();

        assert!(configured_runtime().is_none());

        apply_doh_resolver(reqwest::Client::builder())
            .expect("DoH resolver should initialize default networking runtime");

        let runtime = configured_runtime()
            .expect("networking runtime should be configured after applying DoH resolver");
        assert_eq!(
            runtime
                .doh_servers
                .iter()
                .map(reqwest::Url::to_string)
                .collect::<Vec<_>>(),
            default_doh_servers(),
        );
    }
}
