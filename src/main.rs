use std::{
    fs, io::prelude::*, net::{IpAddr, SocketAddr}, str::FromStr, sync::Arc
};
use std::time::Duration;
use clap::Parser;
use async_channel::unbounded as UnboundedChannel;
use async_channel::{ Receiver, Sender};
use futures::future::join_all;
use trust_dns_client::client::{AsyncClient, ClientHandle};
use trust_dns_client::rr::{DNSClass, Name, RData, RecordType};
use trust_dns_client::udp::UdpClientStream;
use tokio::net::UdpSocket;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use anyhow::Result;
use tracing::{info, warn};
use tokio::sync::Mutex;
use tracing_subscriber;

#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
struct RootDomain {
    name: String,
    addresses: Vec<Address>,
    subdomains: Vec<Subdomain>,
}

#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
struct Subdomain {
    name: String,
    addresses: Vec<Address>,
}

#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
struct Address {
    ip: IpAddr,
}

#[derive(Parser)]
#[clap(author, version, about)]
struct Args {
    #[clap(short, long, help = "target domain")]
    target: String,

    #[clap(
    short,
    long,
    default_value = "8.8.8.8:53",
    help = "default is 8.8.8.8:53"
    )]
    dns_resolver: SocketAddr,

    #[clap(
    short,
    long,
    default_value_t = 1,
    help = "set concurrency level(default is 1)"
    )]
    concurrency: u8,

    #[clap(
    short,
    long,
    default_value = "./dns.txt",
    help = "target subdomains file(default is ./dns.txt)"
    )]
    subdomains_file: String,

    #[clap(
    short,
    long,
    default_value = "./port-scanner.json",
    help = "output file(default is ./port-scanner.json)"
    )]
    output_file: String,
}

async fn get_hostname_ips(client: &mut AsyncClient, hostname: &str) -> Option<Vec<IpAddr>> {
    match Name::from_str(&hostname) {
        Ok(hostname) => {
            let query = client.query(hostname, DNSClass::IN, RecordType::A);
            match query.await {
                Ok(response) => {
                    let mut addresses: Vec<IpAddr> = vec![];

                    for response in response.answers() {
                        match response.data() {
                            Some(record) => match record {
                                RData::A(record) => {
                                    addresses.push(IpAddr::V4(record.to_owned()))
                                }
                                _ => {}
                            },
                            None => {}
                        }
                    }

                    if addresses.len() > 0 {
                        Some(addresses)
                    } else {
                        None
                    }
                } Err(err) => {
                    match err.kind() {
                        trust_dns_client::error::ClientErrorKind::Timeout => {
                            None
                        } _ => {
                            info!("Query Error: {:?}", err);
                            None
                        }
                    }
                }
            }
        }
        Err(err) => {
            info!("Error creating Hostname: {:?}", err);
            None
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .without_time()
        .init();

    let args = Args::parse();

    info!("Target: {:?}", args.target);
    info!("DNS Resolver: {:?}", args.dns_resolver);
    info!("Concurrency: {:?}", args.concurrency);
    info!("Subdomains file: {:?}", args.subdomains_file);
    info!("Output file: {:?}", args.output_file);

    let (s, r): (Sender<String>, Receiver<String>) = UnboundedChannel();
    let target = args.target;
    let dns_resolver = args.dns_resolver;
    let output_file = args.output_file;
    let concurrency = args.concurrency as usize;
    let subdomains_file = args.subdomains_file;
    let timeout = Duration::from_secs(1);
    let stream = UdpClientStream::<UdpSocket>::with_timeout(dns_resolver, timeout);
    let client = AsyncClient::connect(stream);
    let (mut client, bg) = client.await.expect("connection failed");

    tokio::spawn(bg);

    let root_ips = get_hostname_ips(&mut client, &target).await.unwrap_or_else(Vec::new);
    let root_domain = Arc::new(Mutex::new(RootDomain {
        name: target.clone(),
        subdomains: vec![],
        addresses: root_ips.into_iter().map(|ip| Address { ip }).collect(),
    }));
    let found_count = Arc::new(Mutex::new(0));
    let file_subdomains = fs::File::open(subdomains_file).expect("Couldn't read subdomains file");
    let reader = std::io::BufReader::new(file_subdomains);
    let subdomains: Vec<String> = reader
        .lines()
        .map(|l| l.expect("Couldn't read line"))
        .collect();
    let subdomains_len = subdomains.len();
    let progress_bar = ProgressBar::new(subdomains_len as u64);
    progress_bar.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .expect("Couldn't set progress bar style")
        .progress_chars("##-"));
    let progress_send = progress_bar.clone();
    let mut handles = vec![];

    for _ in 0..concurrency {
        let r = r.clone();
        let progress_send = progress_send.clone();
        let found_count_scan = Arc::clone(&found_count);
        let root_domain_scan = Arc::clone(&root_domain);
        let stream = UdpClientStream::<UdpSocket>::with_timeout(dns_resolver, timeout);
        let client = AsyncClient::connect(stream);
        let (mut client, bg) = client.await.expect("connection failed");

        tokio::spawn(bg);

        let handle = tokio::spawn(async move {
            while let Ok(subdomain) = r.recv().await {
                let hostname = format!("{}", subdomain);

                match get_hostname_ips(&mut client, &hostname).await {
                    Some(addresses) => {
                        if !addresses.is_empty() {
                            let subdomain_struct = Subdomain {
                                name: subdomain,
                                addresses: addresses.iter()
                                    .map(|ip| Address { ip: *ip })
                                    .collect::<Vec<Address>>(),
                            };

                            info!("Found {} addresses for {}", addresses.len(), hostname);
                            info!("Addresses: {:?}", addresses);
                            info!("Found {:?}", hostname);

                            {
                                let mut found_count = found_count_scan.lock().await;
                                *found_count += 1;
                            }

                            {
                                let mut root_domain = root_domain_scan.lock().await;
                                root_domain.subdomains.push(subdomain_struct);
                            }

                            info!("Found {:?}", hostname);
                        }
                    } None => {
                        warn!("No IP addresses found for {}", hostname);
                    }
                }

                progress_send.inc(1);
            }
        });

        handles.push(handle);
    }

    for subdomain in subdomains {
        let host = subdomain + "." + &target;
        s.send(host).await.unwrap();
    }
    drop(s);

    join_all(handles).await;

    progress_bar.finish_with_message("Done!");

    {
        let found_count = found_count.lock().await;
        info!("Found {} subdomains.", found_count);
    }

    let root_domain = Arc::try_unwrap(root_domain)
        .expect("Handle to mutex got leaked")
        .into_inner();
    let json = serde_json::to_string(&root_domain).expect("Couldn't serialize root domain");

    info!("JSON: {}", json);

    fs::File::create(&output_file).expect("Could not create output file")
        .write_all(json.as_bytes())
        .expect("Could not write output");

    info!("Wrote output to {}", output_file);

    Ok(())
}
