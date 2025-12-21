use clap::{Parser, ValueEnum};
use hickory_client::client::{Client, ClientHandle};
use hickory_proto::dnssec::rdata::tsig::TsigAlgorithm;
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::tcp::TcpClientStream;
use proc_exit::Code;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use std::{
    fs::File,
    net::{SocketAddr, ToSocketAddrs},
    str::FromStr,
    time::Duration,
};
use tracing::{debug, error};

/// A DNS record type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[value(rename_all = "UPPER")]
enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    NS,
    MX,
    TXT,
    SRV,
}

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// DNS hostname to update
    hostname: String,

    /// DNS record type
    #[arg(value_enum)]
    record_type: DnsRecordType,

    /// DNS record value
    value: String,
    /// Also insert reverse PTR entry
    #[arg(short, long)]
    reverse: bool,

    /// Delete DNS entry
    #[arg(short, long)]
    delete: bool,

    /// DNS TTL
    #[arg(short, long, value_name = "SECONDS", default_value_t = 86400)]
    ttl: u32,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Config {
    server: String,
    key: TsigKey,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct TsigKey {
    name: String,
    algorithm: TsigAlgorithm,
    #[serde_as(as = "Base64")]
    data: Vec<u8>,
}

/// Attempt to find the zone root by querying the configured name server for the
/// hostname, and returning the zone name returned in the name servers in the
/// response
#[tracing::instrument]
async fn find_zone_root(hostname: &str, server: SocketAddr) -> Option<(Name, bool)> {
    debug!("Finding zone root for {} on {}", hostname, server);

    let (stream, sender) = TcpClientStream::new(
        server,
        None,
        Some(Duration::from_secs(1)),
        TokioRuntimeProvider::new(),
    );

    let client = Client::new(stream, sender, None);

    let (mut client, bg) = match client.await {
        Ok(res) => res,
        Err(error) => {
            error!("Unable to connect to DNS server: {}", error);
            return None;
        }
    };

    tokio::spawn(bg);
    let query = client.query(
        Name::from_str(hostname).unwrap(),
        DNSClass::IN,
        RecordType::NS,
    );

    let response = match query.await {
        Ok(res) => res,
        Err(error) => {
            error!("Unable to query server for name {}: {}", hostname, error);
            return None;
        }
    };

    debug!("Response: {:?}", response);

    let name_exists = match response.response_code() {
        hickory_proto::op::ResponseCode::NXDomain => false,
        hickory_proto::op::ResponseCode::NoError => true,
        other => {
            error!("Server returned error: {}", other);
            return None;
        }
    };

    if !response.authoritative() {
        error!("Server is not authoritative for hostname {}", hostname);
        return None;
    }

    match response.name_servers() {
        [] => {
            error!("Server returned no name servers");
            None
        }
        [first, ..] => {
            debug!("Found name server: {:?}", first);
            Some((first.name().clone(), name_exists))
        }
    }
}

#[tokio::main]
async fn main() -> proc_exit::Exit {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let mut config_file = dirs::config_dir().unwrap();
    config_file.push("update-dns");
    config_file.push("config.yml");

    let fd = match File::open(config_file) {
        Ok(file) => file,
        Err(error) => {
            error!("Unable to open config file: {}", error);
            return Code::FAILURE.as_exit();
        }
    };

    let config: Config = match serde_yaml::from_reader(fd) {
        Ok(cfg) => cfg,
        Err(error) => {
            error!("Unable to parse configuration file: {}", error);
            return Code::FAILURE.as_exit();
        }
    };

    let server_addr = match format!("{}:53", config.server).to_socket_addrs() {
        Ok(mut addrs) => addrs.nth(0).unwrap(),
        Err(error) => {
            error!("Unable to resolve server address: {}", error);
            return Code::FAILURE.as_exit();
        }
    };
    debug!(args = ?args,
           server = config.server,
           server_addr = ?server_addr,
           key.name = config.key.name,
           key.algorithm = %config.key.algorithm,
           "Init OK");

    let Some((_root_zone, _name_exists)) = find_zone_root(&args.hostname, server_addr).await else {
        return Code::FAILURE.as_exit();
    };

    Code::SUCCESS.as_exit()
}
