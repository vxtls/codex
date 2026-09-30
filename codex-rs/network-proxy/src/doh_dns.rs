//! Connector adapter for the process-wide DoH resolver.
use codex_http_client::resolve_host_with_doh;
use rama_dns::DnsResolver;
use rama_net::address::Domain;
use std::io;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

/// Resolve TCP destinations through the process-wide DoH runtime.
#[derive(Clone)]
pub(crate) struct DohDnsResolver;

impl DnsResolver for DohDnsResolver {
    type Error = io::Error;

    async fn ipv4_lookup(&self, domain: Domain) -> io::Result<Vec<Ipv4Addr>> {
        Ok(resolve_host_with_doh(domain.as_str(), 0)
            .await?
            .into_iter()
            .filter_map(|addr| match addr.ip() {
                std::net::IpAddr::V4(ip) => Some(ip),
                std::net::IpAddr::V6(_) => None,
            })
            .collect())
    }

    async fn ipv6_lookup(&self, domain: Domain) -> io::Result<Vec<Ipv6Addr>> {
        Ok(resolve_host_with_doh(domain.as_str(), 0)
            .await?
            .into_iter()
            .filter_map(|addr| match addr.ip() {
                std::net::IpAddr::V4(_) => None,
                std::net::IpAddr::V6(ip) => Some(ip),
            })
            .collect())
    }

    async fn txt_lookup(&self, _domain: Domain) -> io::Result<Vec<Vec<u8>>> {
        // TCP connectors only need address lookups. Do not silently fall back to
        // a resolver with different DNS routing for unsupported record types.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the DoH address resolver does not support TXT lookups",
        ))
    }
}

#[cfg(test)]
#[path = "doh_dns_tests.rs"]
mod tests;
