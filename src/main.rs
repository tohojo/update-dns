use anyhow::{Result, bail};
use clap::{Parser, ValueEnum};
use hickory_client::client::{Client, ClientHandle};
use hickory_proto::dnssec::rdata::tsig::TsigAlgorithm;
use hickory_proto::dnssec::tsig::TSigner;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{DNSClass, Name, Record, RecordType, rdata, record_data::RData};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::tcp::TcpClientStream;
use proc_exit::Code;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use std::{
    fs::File,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};
use tracing::{debug, error, info};

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

impl Into<RecordType> for DnsRecordType {
    fn into(self) -> RecordType {
        use DnsRecordType::*;
        match self {
            A => RecordType::A,
            AAAA => RecordType::AAAA,
            CNAME => RecordType::CNAME,
            NS => RecordType::NS,
            MX => RecordType::MX,
            TXT => RecordType::TXT,
            SRV => RecordType::SRV,
        }
    }
}

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// DNS hostname to update
    hostname: Name,

    /// DNS record type
    #[arg(value_enum)]
    record_type: Option<DnsRecordType>,

    /// DNS record value
    value: Option<String>,
    /// Also insert reverse PTR entry
    #[arg(short, long)]
    reverse: bool,

    /// Delete DNS entry
    #[arg(short, long)]
    delete: bool,

    /// Append DNS entry instead of replacing
    #[arg(short, long)]
    append: bool,

    /// DNS TTL
    #[arg(short, long, value_name = "SECONDS", default_value_t = 86400)]
    ttl: u32,
}

impl Args {
    fn to_record(&self) -> Result<Record> {
        use DnsRecordType::*;
        let Some(value) = &self.value else {
            bail!("No value");
        };

        let rdata: RData = match self.record_type {
            Some(A) => RData::A(rdata::A(value.parse::<Ipv4Addr>()?)),
            Some(AAAA) => RData::AAAA(rdata::AAAA(value.parse::<Ipv6Addr>()?)),
            Some(CNAME) => RData::CNAME(rdata::CNAME(Name::from_str_relaxed(value)?)),
            Some(TXT) => RData::TXT(rdata::TXT::new(vec![value.clone()])),
            _ => bail!("No record type"),
        };
        Ok(Record::from_rdata(self.hostname.clone(), self.ttl, rdata))
    }

    fn to_update0(&self) -> Result<Record> {
        let Some(rtype) = &self.record_type else {
            bail!("No record type");
        };
        Ok(Record::update0(
            self.hostname.clone(),
            self.ttl,
            rtype.clone().into(),
        ))
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Config {
    server: String,
    key: TsigKey,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct TsigKey {
    name: Name,
    algorithm: TsigAlgorithm,
    #[serde_as(as = "Base64")]
    data: Vec<u8>,
}

async fn delete_name(args: &Args, zone: &Name, client: &mut Client) -> anyhow::Result<()> {
    let response = match args.to_update0() {
        Ok(record) => {
            info!(
                "Deleting type {} for name {}",
                record.record_type(),
                args.hostname
            );
            client.delete_rrset(record, zone.clone()).await?
        }
        Err(_) => {
            info!("Deleting all RRSETs for name {}", args.hostname);
            client
                .delete_all(args.hostname.clone(), zone.clone(), DNSClass::IN)
                .await?
        }
    };
    match response.response_code() {
        ResponseCode::NoError => Ok(()),
        other => {
            bail!("Server returned error: {}", other);
        }
    }
}

async fn update_name(
    args: &Args,
    zone: &Name,
    name_exists: bool,
    client: &mut Client,
) -> anyhow::Result<()> {
    let record = args.to_record()?;

    if name_exists {
        if args.append {
            info!("Appending record {}", record);
            let response = client.append(record, zone.clone(), true).await?;
            if response.response_code() != ResponseCode::NoError {
                bail!("Server returned error: {}", response.response_code());
            }
            return Ok(());
        } else {
            let update0 = args.to_update0()?;
            info!(
                "Deleting type {} for name {}",
                update0.record_type(),
                args.hostname
            );
            let response = client.delete_rrset(update0, zone.clone()).await?;
            if response.response_code() != ResponseCode::NoError {
                bail!("Server returned error: {}", response.response_code());
            }
        }
    }

    info!("Creating record {}", record);
    let response = client.create(record, zone.clone()).await?;
    debug!(response = ?response, "Received response");
    if response.response_code() != ResponseCode::NoError {
        bail!("Server returned error: {}", response.response_code());
    }
    Ok(())
}

async fn create_client(server: SocketAddr, tsig_key: TsigKey) -> anyhow::Result<Client> {
    let (stream, sender) = TcpClientStream::new(
        server,
        None,
        Some(Duration::from_secs(1)),
        TokioRuntimeProvider::new(),
    );

    let (client, bg) = Client::new(
        stream,
        sender,
        Some(Arc::new(TSigner::new(
            tsig_key.data,
            tsig_key.algorithm,
            tsig_key.name,
            60,
        )?)),
    )
    .await?;
    tokio::spawn(bg);
    Ok(client)
}

/// Attempt to find the zone root by querying the configured name server for the
/// hostname, and returning the zone name returned in the name servers in the
/// response
async fn find_zone_root(
    hostname: &Name,
    new_type: Option<DnsRecordType>,
    client: &mut Client,
) -> Option<(Name, bool)> {
    debug!("Finding zone root for {}", hostname);

    let mut name_exists = false;

    let query = client.query(hostname.clone(), DNSClass::IN, RecordType::ANY);
    let ns_query = client.query(hostname.clone(), DNSClass::IN, RecordType::NS);

    let response = match query.await {
        Ok(res) => res,
        Err(error) => {
            error!("Unable to query server for name {}: {}", hostname, error);
            return None;
        }
    };

    let ns_response = match ns_query.await {
        Ok(res) => res,
        Err(error) => {
            error!("Unable to query server for name {}: {}", hostname, error);
            return None;
        }
    };

    debug!(response = ?response, ns_response= ?ns_response, "Queried server for {}", hostname);

    match response.response_code() {
        ResponseCode::NXDomain => (),
        ResponseCode::NoError => (),
        other => {
            error!("Server returned error: {}", other);
            return None;
        }
    };

    if !response.authoritative() {
        error!("Server is not authoritative for hostname {}", hostname);
        return None;
    }

    for resp in response.answers() {
        if resp.record_type().is_rrsig() {
            continue;
        }
        if new_type.is_none() || resp.record_type() == new_type.unwrap().into() {
            name_exists = true
        }
        info!(
            "Found: {} {} {} {}",
            resp.name().to_string().trim_end_matches("."),
            resp.ttl(),
            resp.record_type(),
            resp.data()
        );
    }

    match ns_response.name_servers() {
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
           key.name = %config.key.name,
           key.algorithm = %config.key.algorithm,
           "Init OK");

    if !args.delete && (args.record_type.is_none() || args.value.is_none()) {
        error!("Must supply both record type and value when not deleting");
        return Code::FAILURE.as_exit();
    }

    let Ok(mut client) = create_client(server_addr, config.key).await else {
        return Code::FAILURE.as_exit();
    };

    let Some((root_zone, name_exists)) =
        find_zone_root(&args.hostname, args.record_type, &mut client).await
    else {
        return Code::FAILURE.as_exit();
    };

    if args.delete {
        if !name_exists {
            error!("Can't delete name {} that doesn't exist", args.hostname);
            return Code::FAILURE.as_exit();
        }
        match delete_name(&args, &root_zone, &mut client).await {
            Ok(_) => Code::SUCCESS.as_exit(),
            Err(error) => {
                error!("Error deleting name: {}", error);
                Code::FAILURE.as_exit()
            }
        }
    } else {
        match update_name(&args, &root_zone, name_exists, &mut client).await {
            Ok(_) => Code::SUCCESS.as_exit(),
            Err(error) => {
                error!("Error updating name: {}", error);
                Code::FAILURE.as_exit()
            }
        }
    }
}
