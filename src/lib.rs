mod dns;
mod packet;
mod utils;

use crate::dns::{DnsPacket, DnsQuestion, QueryType, ResultCode};
use crate::packet::BytePacketBuffer;
use crate::utils::Result as DnsResult;

use std::net::{Ipv4Addr, UdpSocket};

pub type Result<T> = DnsResult<T>;

fn lookup(query_name: &str, query_type: QueryType, server: (Ipv4Addr, u16)) -> Result<DnsPacket> {
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();
    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    let question = DnsQuestion::new(query_name.to_string(), query_type);
    packet.questions.push(question);

    let mut request = BytePacketBuffer::new();
    packet.write(&mut request)?;
    socket.send_to(&request.buffer[0..request.position], server)?;

    let mut response = BytePacketBuffer::new();
    socket.recv_from(&mut response.buffer)?;

    DnsPacket::from_buffer(&mut response)
}

fn recursive_lookup(query_name: &str, query_type: QueryType) -> Result<DnsPacket> {
    let mut ns = "198.41.0.4".parse::<Ipv4Addr>()?;

    println!("\nlookup:\n");

    loop {
        println!(
            "attempting lookup of {:?} {} with ns {}",
            query_type, query_name, ns
        );

        let ns_copy = ns;

        let server = (ns_copy, 53);
        let response = lookup(query_name, query_type, server)?;

        if !response.answers.is_empty() && response.header.result_code == ResultCode::NOERROR {
            return Ok(response);
        }

        if response.header.result_code == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        if let Some(new_ns) = response.get_resolved_ns(query_name) {
            ns = new_ns;
            continue;
        }

        let new_ns_name = match response.get_unresolved_ns(query_name) {
            Some(ns_name) => ns_name,
            _ => return Ok(response),
        };

        let recursive_response = recursive_lookup(&new_ns_name, QueryType::A)?;

        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }
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
        println!("\nreceived query:\n\n{:?}", question);

        if let Ok(result) = recursive_lookup(&question.name, question.query_type) {
            packet.questions.push(question.clone());
            packet.header.result_code = result.header.result_code;

            if !result.answers.is_empty() {
                println!("\nanswer:\n");
            }

            for answer in result.answers {
                println!("{:?}", answer);
                packet.answers.push(answer);
            }

            if !result.authorities.is_empty() {
                println!("\nauthorities:\n");
            }

            for authority in result.authorities {
                println!("{:?}", authority);
                packet.authorities.push(authority);
            }

            if !result.resources.is_empty() {
                println!("\resources:\n");
            }

            for resource in result.resources {
                println!("{:?}", resource);
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
    let response = response.get_range(0, len)?;

    socket.send_to(response, src)?;

    Ok(())
}
