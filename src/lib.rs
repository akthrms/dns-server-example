mod dns;
mod packet;
mod utils;

use crate::dns::{Packet, QueryType, Question, ResponseCode};
use crate::packet::BytePacketBuffer;
use crate::utils::Result as DnsResult;
use log::debug;
use std::net::{Ipv4Addr, UdpSocket};

pub type Result<T> = DnsResult<T>;

fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> Result<Packet> {
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = Packet::new();
    packet.header.id = 6666;
    packet.header.qdcount = 1;
    packet.header.rd = true;
    packet
        .questions
        .push(Question::new(qname.to_string(), qtype));

    let mut request = BytePacketBuffer::new();
    packet.write(&mut request)?;
    socket.send_to(&request.buffer[0..request.position], server)?;

    let mut response = BytePacketBuffer::new();
    socket.recv_from(&mut response.buffer)?;

    Packet::from_buffer(&mut response)
}

fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<Packet> {
    let mut ns = "198.41.0.4".parse::<Ipv4Addr>()?;

    loop {
        debug!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

        let server = (ns.clone(), 53);
        let response = lookup(qname, qtype, server)?;

        if !response.answers.is_empty() && response.header.rcode == ResponseCode::NOERROR {
            return Ok(response);
        }

        if response.header.rcode == ResponseCode::NXDOMAIN {
            return Ok(response);
        }

        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns;
            continue;
        }

        let new_ns_name = match response.get_unresolved_ns(qname) {
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
    let mut request = Packet::from_buffer(&mut request)?;

    let mut packet = Packet::new();
    packet.header.id = request.header.id;
    packet.header.rd = true;
    packet.header.ra = true;
    packet.header.response = true;

    if let Some(question) = request.questions.pop() {
        debug!("question: {:?}", question);

        if let Ok(result) = recursive_lookup(&question.qname, question.qtype) {
            packet.questions.push(question.clone());
            packet.header.rcode = result.header.rcode;

            for answer in result.answers {
                debug!("answer: {:?}", answer);
                packet.answers.push(answer);
            }

            for authority in result.authorities {
                debug!("authority: {:?}", authority);
                packet.authorities.push(authority);
            }

            for addition in result.additions {
                debug!("addition: {:?}", addition);
                packet.additions.push(addition);
            }
        } else {
            packet.header.rcode = ResponseCode::SERVFAIL;
        }
    } else {
        packet.header.rcode = ResponseCode::FORMERR;
    }

    let mut response = BytePacketBuffer::new();
    packet.write(&mut response)?;

    let len = response.position;
    let response = response.get_range(0, len)?;

    socket.send_to(response, src)?;

    Ok(())
}
