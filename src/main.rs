// SPDX-License-Identifier: GPL-3.0-or-later
use anyhow::{Context, Result, bail, format_err};
use clap::error::ErrorKind;
use clap::{CommandFactory, Parser, ValueEnum};
use hickory_client::client::{Client, ClientHandle};
use hickory_proto::dnssec::rdata::tsig::TsigAlgorithm;
use hickory_proto::dnssec::tsig::TSigner;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{DNSClass, Name, Record, RecordType, rdata, record_data::RData};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::tcp::TcpClientStream;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use std::{
    fs::File,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};
use tracing::{debug, info, warn};

/// A DNS record type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[value(rename_all = "UPPER")]
#[allow(clippy::upper_case_acronyms)]
enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    PTR,
    SRV,
    TXT,
}

#[allow(clippy::from_over_into)]
impl Into<RecordType> for DnsRecordType {
    fn into(self) -> RecordType {
        use DnsRecordType::*;
        match self {
            A => RecordType::A,
            AAAA => RecordType::AAAA,
            CNAME => RecordType::CNAME,
            MX => RecordType::MX,
            NS => RecordType::NS,
            PTR => RecordType::PTR,
            SRV => RecordType::SRV,
            TXT => RecordType::TXT,
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
    value: Vec<String>,
    /// Also insert reverse PTR entry
    #[arg(short, long)]
    reverse: bool,

    /// Delete DNS entry
    #[arg(short, long, group = "extra_action")]
    delete: bool,

    /// Append DNS entry instead of replacing
    #[arg(short, long, group = "extra_action")]
    append: bool,

    /// DNS TTL
    #[arg(short, long, value_name = "SECONDS", default_value_t = 86400)]
    ttl: u32,
}

impl Args {
    /// Create a DNS Record type from the arguments supplied on the command
    /// line, parsing the values into the right types for the given record type
    fn to_record(&self) -> Result<Record> {
        use DnsRecordType::*;
        let value = self.value.first().ok_or(format_err!("Missing value"))?;

        let rdata: RData = match self.record_type.ok_or(format_err!("No record type"))? {
            A => RData::A(rdata::A(value.parse()?)),
            AAAA => RData::AAAA(rdata::AAAA(value.parse()?)),
            CNAME => RData::CNAME(rdata::CNAME(value.parse()?)),
            MX => {
                let [prio, name] = self.value.as_slice() else {
                    bail!("Need two MX data fields (prio and name)");
                };
                RData::MX(rdata::MX::new(
                    prio.parse()
                        .with_context(|| format!("Invalid MX priority '{}'", prio))?,
                    name.parse()?,
                ))
            }
            NS => RData::NS(rdata::NS(value.parse()?)),
            PTR => RData::PTR(rdata::PTR(value.parse()?)),
            SRV => {
                let [prio, weight, port, name] = self.value.as_slice() else {
                    bail!("Need four SRV data fields (prio, weight, port and name)");
                };
                RData::SRV(rdata::SRV::new(
                    prio.parse()
                        .with_context(|| format!("Invalid SRV priority '{}'", prio))?,
                    weight
                        .parse()
                        .with_context(|| format!("Invalid SRV weight '{}'", weight))?,
                    port.parse()
                        .with_context(|| format!("Invalid SRV port '{}'", port))?,
                    name.parse()?,
                ))
            }
            TXT => RData::TXT(rdata::TXT::new(self.value.clone())),
        };
        Ok(Record::from_rdata(self.hostname.clone(), self.ttl, rdata))
    }

    /// Create a reverse (PTR) record for the given arguments.
    ///
    /// Only works for A and AAAA records, errors on other record types
    fn to_reverse_record(&self) -> Result<Record> {
        use DnsRecordType::*;
        let value = self.value.first().ok_or(format_err!("Missing value"))?;

        let ip: IpAddr = match self.record_type.ok_or(format_err!("No record type"))? {
            A => IpAddr::V4(value.parse()?),
            AAAA => IpAddr::V6(value.parse()?),
            t => bail!("Can't reverse record type {:?}", t),
        };

        Ok(Record::from_rdata(
            ip.into(),
            self.ttl,
            RData::PTR(rdata::PTR(self.hostname.clone())),
        ))
    }

    /// Create an Update0 Record from the hostname and record type specified by
    /// the args
    fn to_update0(&self) -> Option<Record> {
        Some(Record::update0(
            self.hostname.clone(),
            self.ttl,
            self.record_type?.into(),
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

/// Delete a record from a zone
/// Helper function to issue a delete of a record and check the response code
async fn delete_record(record: Record, zone: Name, client: &mut Client) -> Result<()> {
    info!(
        "Deleting record type {} for name {}",
        record.record_type(),
        record.name(),
    );

    let response = client.delete_rrset(record, zone).await?;
    debug!(response = ?response, "Received response for delete");
    if response.response_code() != ResponseCode::NoError {
        bail!("Server returned error: {}", response.response_code());
    }
    Ok(())
}

/// Delete a name from DNS.
///
/// If a record type is set, delete only that type, otherwise delete all records
/// for the name given in args.
async fn delete_name(args: &Args, client: &mut Client) -> Result<()> {
    let (zone, responses) =
        find_zone_root(&args.hostname, args.record_type.map(|r| r.into()), client).await?;

    if responses.is_empty() {
        bail!("Can't delete name {} that doesn't exist", args.hostname);
    }

    if let Some(record) = args.to_update0() {
        delete_record(record, zone, client).await?;
    } else {
        info!("Deleting all RRSETs for name {}", args.hostname);
        let response = client
            .delete_all(args.hostname.clone(), zone, DNSClass::IN)
            .await?;

        debug!(response = ?response, "Received response for delete");
        if response.response_code() != ResponseCode::NoError {
            bail!("Server returned error: {}", response.response_code());
        }
    };

    if args.reverse {
        info!("Deleting reverse mappings for removed names");
        for resp in responses {
            let name: Name = match *resp.data() {
                RData::A(rdata::A(v)) => v.into(),
                RData::AAAA(rdata::AAAA(v)) => v.into(),
                _ => continue,
            };
            let (zone, rev_resp) = match find_zone_root(&name, Some(RecordType::PTR), client).await
            {
                Ok(r) => r,
                Err(error) => {
                    warn!("Error deleting reverse name {}: {}", name, error);
                    continue;
                }
            };
            if rev_resp.is_empty() {
                continue;
            }
            let record = Record::update0(name, resp.ttl(), RecordType::PTR);
            match delete_record(record, zone, client).await {
                Ok(_) => (),
                Err(error) => warn!("Error deleting reverse name: {}", error),
            };
        }
    }

    Ok(())
}

/// Update a name in DNS.
///
/// If the append flag is specified in args, add the record to the existing
/// RRset. Otherwise, issue a delete for the given record type first,
/// effectively replacing the record. If no record exists, create a new one.
async fn update_name(args: &Args, reverse: bool, client: &mut Client) -> Result<()> {
    let record = match reverse {
        true => args.to_reverse_record()?,
        false => args.to_record()?,
    };

    let (zone, responses) =
        find_zone_root(record.name(), Some(record.record_type()), client).await?;

    if !responses.is_empty() {
        if args.append {
            info!("Appending record {}", record);
            let response = client.append(record, zone, true).await?;

            debug!(response = ?response, "Received response for append");
            if response.response_code() != ResponseCode::NoError {
                bail!("Server returned error: {}", response.response_code());
            }

            return Ok(());
        } else {
            let update0 =
                Record::update0(record.name().clone(), record.ttl(), record.record_type());
            delete_record(update0, zone.clone(), client).await?;
        }
    }

    info!("Creating record {}", record);
    let response = client.create(record, zone).await?;

    debug!(response = ?response, "Received response for create");
    if response.response_code() != ResponseCode::NoError {
        bail!("Server returned error: {}", response.response_code());
    }
    Ok(())
}

/// Create a new hickory_client client object.
///
/// Attach a TSig signer object, and spawn the background task to handle
/// communication
async fn create_client(server: SocketAddr, tsig_key: TsigKey) -> Result<Client> {
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

/// Attempt to find the zone root
///
/// Query the configured name server for the hostname and NS servers, and return
/// the zone name returned in the NS response along with a boolean indicating
/// whether a record of the given new_type exists in DNS.
async fn find_zone_root(
    hostname: &Name,
    new_type: Option<RecordType>,
    client: &mut Client,
) -> Result<(Name, Vec<Record>)> {
    debug!("Finding zone root for {}", hostname);

    let mut response = client
        .query(hostname.clone(), DNSClass::IN, RecordType::ANY)
        .await?;
    let ns_response = client
        .query(hostname.clone(), DNSClass::IN, RecordType::NS)
        .await?;

    debug!(response = ?response, ns_response= ?ns_response, "Queried server for {}", hostname);

    match response.response_code() {
        ResponseCode::NXDomain => (),
        ResponseCode::NoError => (),
        other => bail!("Server returned error: {}", other),
    };

    match ns_response.response_code() {
        ResponseCode::NXDomain => (),
        ResponseCode::NoError => (),
        other => bail!("Server returned error: {}", other),
    };

    if !response.authoritative() {
        bail!("Server is not authoritative for hostname {}", hostname);
    }

    for resp in response.answers() {
        if resp.record_type().is_rrsig() {
            continue;
        }
        info!(
            "Found: {} {} {} {}",
            resp.name().to_string().trim_end_matches("."),
            resp.ttl(),
            resp.record_type(),
            resp.data()
        );
    }

    let responses: Vec<Record> = response
        .answers_mut()
        .extract_if(.., |r| {
            !r.record_type().is_rrsig()
                && (new_type.is_none() || r.record_type() == new_type.unwrap())
        })
        .collect();

    match ns_response.name_servers() {
        [] => Err(format_err!("Server returned no name servers")),
        [first, ..] => {
            debug!("Found name server: {:?}", first);
            Ok((first.name().clone(), responses))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    if !args.delete && (args.record_type.is_none() || args.value.is_empty()) {
        Args::command()
            .error(
                ErrorKind::ArgumentConflict,
                "Must supply both record type and value when not deleting",
            )
            .exit();
    }
    if args.reverse {
        use DnsRecordType::*;
        match args.record_type {
            Some(A) => (),
            Some(AAAA) => (),
            None => (), // for delete all
            _ => {
                Args::command()
                    .error(
                        ErrorKind::ArgumentConflict,
                        "Can only use --reverse with A and AAAA records",
                    )
                    .exit();
            }
        };
    }

    let mut config_file = dirs::config_dir().ok_or(format_err!("Couldn't get config directory"))?;
    config_file.push("update-dns");
    config_file.push("config.yml");

    let config: Config = serde_yaml::from_reader(
        File::open(config_file).context("Unable to open configuration file")?,
    )
    .context("Unable to parse configuration file")?;

    let server_addr = format!("{}:53", config.server)
        .to_socket_addrs()
        .context("Unable to resolve server address")?
        .next()
        .ok_or(format_err!("No server address from resolver"))?;
    debug!(args = ?args,
           server = config.server,
           server_addr = ?server_addr,
           key.name = %config.key.name,
           key.algorithm = %config.key.algorithm,
           "Init OK");

    let mut client = create_client(server_addr, config.key)
        .await
        .context("Couldn't create DNS client")?;

    if args.delete {
        delete_name(&args, &mut client)
            .await
            .context("Couldn't delete name")?;
    } else {
        update_name(&args, false, &mut client)
            .await
            .context("Couldn't update name")?;

        if args.reverse {
            info!("Generating reverse record");
            update_name(&args, true, &mut client)
                .await
                .context("Couldn't generate reverse record")?;
        }
    }
    Ok(())
}
