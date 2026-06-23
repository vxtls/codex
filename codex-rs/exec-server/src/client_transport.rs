use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use codex_client::log_request_metadata;
use codex_client::resolve_host_with_doh;
use tokio::io::AsyncBufReadExt;
use tokio::io::BufReader;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::timeout;
use tokio_tungstenite::MaybeTlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::client_async_tls_with_config;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tracing::debug;
use tracing::warn;

use codex_utils_rustls_provider::ensure_rustls_crypto_provider;

use crate::ExecServerClient;
use crate::ExecServerError;
use crate::client_api::DEFAULT_REMOTE_EXEC_SERVER_CONNECT_TIMEOUT;
use crate::client_api::DEFAULT_REMOTE_EXEC_SERVER_INITIALIZE_TIMEOUT;
use crate::client_api::ExecServerClientConnectOptions;
use crate::client_api::NoiseRendezvousConnectArgs;
use crate::client_api::NoiseRendezvousConnectBundle;
use crate::client_api::NoiseRendezvousConnectProvider;
use crate::client_api::RemoteExecServerConnectArgs;
use crate::client_api::StdioExecServerCommand;
use crate::client_api::StdioExecServerConnectArgs;
use crate::connection::JsonRpcConnection;
use crate::noise_channel::NoiseChannelIdentity;
use crate::noise_relay::NoiseHarnessConnectionArgs;
use crate::noise_relay::noise_harness_connection_from_websocket;
use crate::noise_relay::noise_relay_websocket_config;
use crate::relay::harness_connection_from_websocket;

const ENVIRONMENT_CLIENT_NAME: &str = "codex-environment";

/// Reopens the transport for one logical exec-server client session.
///
/// URL connections reuse their configured endpoint. Noise connections retain
/// the harness identity but fetch a fresh single-use authorization bundle for
/// every physical connection attempt.
#[derive(Clone)]
pub(crate) enum ExecServerReconnectStrategy {
    WebSocket(RemoteExecServerConnectArgs),
    NoiseRendezvous {
        provider: Arc<dyn NoiseRendezvousConnectProvider>,
        identity: NoiseChannelIdentity,
        client_name: String,
        connect_timeout: Duration,
        initialize_timeout: Duration,
    },
}

impl ExecServerReconnectStrategy {
    pub(crate) async fn resume(
        &self,
        session_id: &str,
    ) -> Result<(JsonRpcConnection, ExecServerClientConnectOptions), ExecServerError> {
        match self {
            Self::WebSocket(args) => {
                let mut args = args.clone();
                args.resume_session_id = Some(session_id.to_string());
                let connection = ExecServerClient::open_websocket_connection(&args).await?;
                Ok((connection, args.into()))
            }
            Self::NoiseRendezvous {
                provider,
                identity,
                client_name,
                connect_timeout,
                initialize_timeout,
            } => {
                let bundle = provider.connect_bundle(identity.public_key()).await?;
                ExecServerClient::open_noise_rendezvous_connection(NoiseRendezvousConnectArgs {
                    bundle,
                    harness_identity: identity.clone(),
                    client_name: client_name.clone(),
                    connect_timeout: *connect_timeout,
                    initialize_timeout: *initialize_timeout,
                    resume_session_id: Some(session_id.to_string()),
                })
                .await
            }
        }
    }
}

impl ExecServerClient {
    /// Open the selected transport and run the common JSON-RPC initialization.
    /// Noise connection details are fetched here so reconnects get a fresh URL
    /// and authorization without replacing the harness identity.
    pub(crate) async fn connect_for_transport(
        transport_params: crate::client_api::ExecServerTransportParams,
    ) -> Result<Self, ExecServerError> {
        match transport_params {
            crate::client_api::ExecServerTransportParams::WebSocketUrl {
                websocket_url,
                connect_timeout,
                initialize_timeout,
            } => {
                Self::connect_websocket(RemoteExecServerConnectArgs {
                    websocket_url,
                    client_name: ENVIRONMENT_CLIENT_NAME.to_string(),
                    connect_timeout,
                    initialize_timeout,
                    resume_session_id: None,
                })
                .await
            }
            crate::client_api::ExecServerTransportParams::NoiseRendezvous {
                provider,
                identity,
            } => {
                let reconnect_strategy = ExecServerReconnectStrategy::NoiseRendezvous {
                    provider: Arc::clone(&provider),
                    identity: identity.clone(),
                    client_name: ENVIRONMENT_CLIENT_NAME.to_string(),
                    connect_timeout: DEFAULT_REMOTE_EXEC_SERVER_CONNECT_TIMEOUT,
                    initialize_timeout: DEFAULT_REMOTE_EXEC_SERVER_INITIALIZE_TIMEOUT,
                };
                let (connection, options) =
                    Self::open_initial_noise_rendezvous_connection(&provider, &identity).await?;
                Self::connect_with_recovery(connection, options, Some(reconnect_strategy)).await
            }
            crate::client_api::ExecServerTransportParams::StdioCommand {
                command,
                initialize_timeout,
            } => {
                Self::connect_stdio_command(StdioExecServerConnectArgs {
                    command,
                    client_name: ENVIRONMENT_CLIENT_NAME.to_string(),
                    initialize_timeout,
                    resume_session_id: None,
                })
                .await
            }
        }
    }

    async fn open_initial_noise_rendezvous_connection(
        provider: &Arc<dyn NoiseRendezvousConnectProvider>,
        identity: &NoiseChannelIdentity,
    ) -> Result<(JsonRpcConnection, ExecServerClientConnectOptions), ExecServerError> {
        let open_connection = |bundle: NoiseRendezvousConnectBundle| {
            Self::open_noise_rendezvous_connection(NoiseRendezvousConnectArgs {
                bundle,
                harness_identity: identity.clone(),
                client_name: ENVIRONMENT_CLIENT_NAME.to_string(),
                connect_timeout: DEFAULT_REMOTE_EXEC_SERVER_CONNECT_TIMEOUT,
                initialize_timeout: DEFAULT_REMOTE_EXEC_SERVER_INITIALIZE_TIMEOUT,
                resume_session_id: None,
            })
        };
        let bundle = provider.connect_bundle(identity.public_key()).await?;
        match open_connection(bundle).await {
            Err(error)
                if matches!(
                    &error,
                    ExecServerError::WebSocketConnect { source, .. }
                        if matches!(
                            source,
                            tokio_tungstenite::tungstenite::Error::Http(response)
                                if response.status().as_u16() == 401
                        )
                ) =>
            {
                let bundle = provider.connect_bundle(identity.public_key()).await?;
                open_connection(bundle).await
            }
            result => result,
        }
    }

    pub async fn connect_websocket(
        args: RemoteExecServerConnectArgs,
    ) -> Result<Self, ExecServerError> {
        let connection = Self::open_websocket_connection(&args).await?;
        let options = args.clone().into();
        Self::connect_with_recovery(
            connection,
            options,
            Some(ExecServerReconnectStrategy::WebSocket(args)),
        )
        .await
    }

    pub(crate) async fn open_websocket_connection(
        args: &RemoteExecServerConnectArgs,
    ) -> Result<JsonRpcConnection, ExecServerError> {
        ensure_rustls_crypto_provider();
        let websocket_url = args.websocket_url.clone();
        let connect_timeout = args.connect_timeout;
        let stream = connect_websocket_url_with_doh(
            websocket_url.as_str(),
            websocket_url.as_str(),
            connect_timeout,
            None,
        )
        .await?;

        let connection_label = format!("exec-server websocket {websocket_url}");
        let connection = if is_rendezvous_harness_url(&websocket_url) {
            harness_connection_from_websocket(stream, connection_label)
        } else {
            JsonRpcConnection::from_websocket(stream, connection_label)
        };
        Ok(connection)
    }

    /// Connect to one exec-server through an authenticated rendezvous stream
    /// using a caller-supplied single-use authorization bundle.
    ///
    /// The executor key is pinned before JSON-RPC starts; the websocket carries
    /// only ciphertext after that. Environment-managed connections use a
    /// retained [`NoiseRendezvousConnectProvider`] so recovery can fetch a fresh
    /// bundle for each reconnect.
    pub async fn connect_noise_rendezvous(
        args: NoiseRendezvousConnectArgs,
    ) -> Result<Self, ExecServerError> {
        let (connection, options) = Self::open_noise_rendezvous_connection(args).await?;
        Self::connect(connection, options).await
    }

    pub(crate) async fn open_noise_rendezvous_connection(
        args: NoiseRendezvousConnectArgs,
    ) -> Result<(JsonRpcConnection, ExecServerClientConnectOptions), ExecServerError> {
        ensure_rustls_crypto_provider();
        // Keep the registry-issued URL, key, and authorization together for this
        // connection attempt.
        let NoiseRendezvousConnectArgs {
            bundle,
            harness_identity,
            client_name,
            connect_timeout,
            initialize_timeout,
            resume_session_id,
        } = args;
        let NoiseRendezvousConnectBundle {
            websocket_url,
            environment_id,
            executor_registration_id,
            executor_public_key,
            harness_key_authorization,
        } = bundle;
        let diagnostic_url = websocket_url
            .split(['?', '#'])
            .next()
            .unwrap_or(websocket_url.as_str())
            .to_string();
        let stream = connect_websocket_url_with_doh(
            websocket_url.as_str(),
            diagnostic_url.as_str(),
            connect_timeout,
            Some(noise_relay_websocket_config()),
        )
        .await?;

        let connection_label = format!("Noise exec-server rendezvous websocket {diagnostic_url}");
        let connection = noise_harness_connection_from_websocket(
            stream,
            NoiseHarnessConnectionArgs {
                connection_label,
                environment_id,
                executor_registration_id,
                identity: harness_identity,
                responder_public_key: executor_public_key,
                harness_key_authorization,
            },
        );
        Ok((
            connection,
            ExecServerClientConnectOptions {
                client_name,
                initialize_timeout,
                resume_session_id,
            },
        ))
    }

    pub(crate) async fn connect_stdio_command(
        args: StdioExecServerConnectArgs,
    ) -> Result<Self, ExecServerError> {
        let mut child = stdio_command_process(&args.command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(ExecServerError::Spawn)?;

        let stdin = child.stdin.take().ok_or_else(|| {
            ExecServerError::Protocol("spawned exec-server command has no stdin".to_string())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            ExecServerError::Protocol("spawned exec-server command has no stdout".to_string())
        })?;
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                loop {
                    match lines.next_line().await {
                        Ok(Some(line)) => debug!("exec-server stdio stderr: {line}"),
                        Ok(None) => break,
                        Err(err) => {
                            warn!("failed to read exec-server stdio stderr: {err}");
                            break;
                        }
                    }
                }
            });
        }

        Self::connect(
            JsonRpcConnection::from_stdio(stdout, stdin, "exec-server stdio command".to_string())
                .with_child_process(child),
            args.into(),
        )
        .await
    }
}

async fn connect_websocket_url_with_doh(
    websocket_url: &str,
    diagnostic_url: &str,
    connect_timeout: Duration,
    websocket_config: Option<WebSocketConfig>,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, ExecServerError> {
    let connect_start = std::time::Instant::now();
    let uri: tokio_tungstenite::tungstenite::http::Uri =
        websocket_url.parse().map_err(|error| {
            ExecServerError::Protocol(format!(
                "invalid exec-server websocket URL `{diagnostic_url}`: {error}"
            ))
        })?;
    let host = uri.host().ok_or_else(|| {
        ExecServerError::Protocol(format!("websocket URL `{diagnostic_url}` is missing host"))
    })?;
    let port = uri.port_u16().unwrap_or_else(|| match uri.scheme_str() {
        Some("wss") => 443,
        _ => 80,
    });
    let addrs = resolve_host_with_doh(host, port).await.map_err(|error| {
        let message = format!("DoH resolution failed for `{diagnostic_url}`: {error}");
        log_request_metadata(
            "ws",
            "GET",
            diagnostic_url,
            None,
            connect_start.elapsed(),
            Some(message.as_str()),
        );
        ExecServerError::Protocol(message)
    })?;
    let mut tcp_stream = None;
    let mut last_connect_error = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                tcp_stream = Some(stream);
                break;
            }
            Err(error) => {
                last_connect_error = Some(error);
            }
        }
    }
    let Some(tcp_stream) = tcp_stream else {
        let message = last_connect_error.map_or_else(
            || format!("failed to connect to exec-server websocket `{diagnostic_url}`"),
            |error| {
                format!("failed to connect to exec-server websocket `{diagnostic_url}`: {error}")
            },
        );
        log_request_metadata(
            "ws",
            "GET",
            diagnostic_url,
            None,
            connect_start.elapsed(),
            Some(message.as_str()),
        );
        return Err(ExecServerError::Protocol(message));
    };
    let request = websocket_url.into_client_request().map_err(|error| {
        ExecServerError::Protocol(format!(
            "invalid exec-server websocket request `{diagnostic_url}`: {error}"
        ))
    })?;
    let (stream, response) = timeout(
        connect_timeout,
        client_async_tls_with_config(request, tcp_stream, websocket_config, None),
    )
    .await
    .map_err(|_| {
        let message = format!(
            "timed out connecting to exec-server websocket `{diagnostic_url}` after {connect_timeout:?}"
        );
        log_request_metadata(
            "ws",
            "GET",
            diagnostic_url,
            None,
            connect_start.elapsed(),
            Some(message.as_str()),
        );
        ExecServerError::WebSocketConnectTimeout {
            url: diagnostic_url.to_string(),
            timeout: connect_timeout,
        }
    })?
    .map_err(|source| ExecServerError::WebSocketConnect {
        url: diagnostic_url.to_string(),
        source,
    })
    .map_err(|error| {
        let message = error.to_string();
        log_request_metadata(
            "ws",
            "GET",
            diagnostic_url,
            None,
            connect_start.elapsed(),
            Some(message.as_str()),
        );
        error
    })?;
    log_request_metadata(
        "ws",
        "GET",
        diagnostic_url,
        Some(response.status().as_u16()),
        connect_start.elapsed(),
        None,
    );
    Ok(stream)
}

fn is_rendezvous_harness_url(websocket_url: &str) -> bool {
    let Some((_path, query)) = websocket_url.split_once('?') else {
        return false;
    };
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .any(|(key, value)| key == "role" && value == "harness")
}

fn stdio_command_process(stdio_command: &StdioExecServerCommand) -> Command {
    let mut command = Command::new(&stdio_command.program);
    command.args(&stdio_command.args);
    command.envs(&stdio_command.env);
    if let Some(cwd) = &stdio_command.cwd {
        command.current_dir(cwd);
    }
    #[cfg(unix)]
    command.process_group(0);
    command
}

#[cfg(test)]
#[path = "client_transport_tests.rs"]
mod tests;
