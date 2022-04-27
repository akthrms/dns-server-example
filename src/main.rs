use dns_server_example::{handle_query, Result};
use std::net::UdpSocket;

fn main() -> Result<()> {
    let host = "0.0.0.0";
    let port = 2053;

    let socket = UdpSocket::bind((host, port))?;
    println!(
        "🚀 DNS cache server started [host: {}, port: {}]",
        host, port
    );

    loop {
        if let Err(e) = handle_query(&socket) {
            eprintln!("an error occurred: {}", e)
        }
    }
}
