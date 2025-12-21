use clap::{Parser, ValueEnum};
use hickory_proto::dnssec::rdata::tsig::TsigAlgorithm;
use proc_exit::Code;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use std::fs::File;
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

fn main() -> proc_exit::Exit {
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
    debug!(args = ?args,
           server = config.server,
           key.name = config.key.name,
           key.algorithm = %config.key.algorithm,
           "Init OK");

    Code::SUCCESS.as_exit()
}
