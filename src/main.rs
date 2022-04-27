use dns_server_example::{handle_query, Result};
use log::{debug, error};
use std::net::UdpSocket;

fn main() -> Result<()> {
    env_logger::init();

    let server = ("0.0.0.0", 2053);
    let socket = UdpSocket::bind(server)?;

    debug!("DNS cache server started at {:?}", server);

    loop {
        if let Err(e) = handle_query(&socket) {
            error!("an error occurred: {}", e);
        }
    }
}
