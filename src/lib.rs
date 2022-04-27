mod dns;
mod packet;
mod utils;

use crate::dns::{DnsPacket, DnsQuestion, QueryType, ResultCode};
use crate::packet::BytePacketBuffer;
use crate::utils::Result as DnsResult;

use std::net::UdpSocket;

pub type Result<T> = DnsResult<T>;

fn lookup(query_name: &str, query_type: QueryType) -> Result<DnsPacket> {
    let google_public_dns = ("8.8.8.8", 53);
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();
    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    let question = DnsQuestion::new(query_name.to_string(), query_type);
    packet.questions.push(question);

    let mut request = BytePacketBuffer::new();
    packet.write(&mut request)?;
    socket.send_to(&request.buffer[0..request.position], google_public_dns)?;

    let mut response = BytePacketBuffer::new();
    socket.recv_from(&mut response.buffer)?;

    DnsPacket::from_buffer(&mut response)
}

pub fn handle_query(socket: &UdpSocket) -> Result<()> {
    let mut request = BytePacketBuffer::new();
    let (_, src) = socket.recv_from(&mut request.buffer)?;
    let mut request = DnsPacket::from_buffer(&mut request)?;

    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.response = true;

    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);

        if let Ok(result) = lookup(&question.name, question.query_type) {
            packet.questions.push(question);
            packet.header.result_code = result.header.result_code;

            for answer in result.answers {
                println!("Answer: {:?}", answer);
                packet.answers.push(answer);
            }

            for authority in result.authorities {
                println!("Authority: {:?}", authority);
                packet.authorities.push(authority);
            }

            for resource in result.resources {
                println!("Resource: {:?}", resource);
                packet.resources.push(resource);
            }
        } else {
            packet.header.result_code = ResultCode::SERVFAIL;
        }
    } else {
        packet.header.result_code = ResultCode::FORMERR;
    }

    let mut response = BytePacketBuffer::new();
    packet.write(&mut response)?;

    let len = response.position;
    let data = response.get_range(0, len)?;

    socket.send_to(data, src)?;

    Ok(())
}
