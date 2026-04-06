mod custom_ca;
mod default_client;
mod error;
mod networking;
mod request;
mod retry;
mod sse;
mod telemetry;
mod transport;

pub use crate::custom_ca::BuildCustomCaTransportError;
/// Test-only subprocess hook for custom CA coverage.
///
/// This stays public only so the `custom_ca_probe` binary target can reuse the shared helper. It
/// is hidden from normal docs because ordinary callers should use
/// [`build_reqwest_client_with_custom_ca`] instead.
#[doc(hidden)]
pub use crate::custom_ca::build_reqwest_client_for_subprocess_tests;
pub use crate::custom_ca::build_reqwest_client_with_custom_ca;
pub use crate::custom_ca::maybe_build_rustls_client_config_with_custom_ca;
pub use crate::default_client::CodexHttpClient;
pub use crate::default_client::CodexRequestBuilder;
pub use crate::error::StreamError;
pub use crate::error::TransportError;
pub use crate::networking::NetworkRuntimeConfig;
pub use crate::networking::NetworkRuntimeConfigError;
pub use crate::networking::apply_doh_resolver_blocking;
pub use crate::networking::configure_networking;
pub use crate::networking::default_doh_servers;
pub use crate::networking::ensure_networking_configured_with_defaults;
pub use crate::networking::log_request_metadata;
pub use crate::networking::resolve_host_with_doh;
pub use crate::request::Request;
pub use crate::request::RequestCompression;
pub use crate::request::Response;
pub use crate::retry::RetryOn;
pub use crate::retry::RetryPolicy;
pub use crate::retry::backoff;
pub use crate::retry::run_with_retry;
pub use crate::sse::sse_stream;
pub use crate::telemetry::RequestTelemetry;
pub use crate::transport::ByteStream;
pub use crate::transport::HttpTransport;
pub use crate::transport::ReqwestTransport;
pub use crate::transport::StreamResponse;
