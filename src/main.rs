use clap::{Parser, ValueEnum};

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

fn main() {
    let args = Args::parse();

    println!("Hello, world! {:?}", args);
}
