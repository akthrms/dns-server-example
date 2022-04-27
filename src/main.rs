use dns_server_example::{handle_query, Result};
use std::net::UdpSocket;

fn main() -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    loop {
        if let Err(e) = handle_query(&socket) {
            eprintln!("An error occurred: {}", e)
        }
    }
}
