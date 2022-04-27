use crate::packet::BytePacketBuffer;
use crate::utils::Result;

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR,
    FORMERR,
    SERVFAIL,
    NXDOMAIN,
    NOTIMP,
    REFUSED,
}

impl From<u8> for ResultCode {
    fn from(num: u8) -> Self {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            _ => ResultCode::NOERROR,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub recursion_desired: bool,
    pub truncated_message: bool,
    pub authoritative_answer: bool,
    pub operation_code: u8,
    pub response: bool,
    pub result_code: ResultCode,
    pub checking_disabled: bool,
    pub authenticated_data: bool,
    pub z: bool,
    pub recursion_available: bool,
    pub questions: u16,
    pub answers: u16,
    pub authoritative_entries: u16,
    pub resource_entries: u16,
}

impl DnsHeader {
    fn new() -> Self {
        Self {
            id: 0,
            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            operation_code: 0,
            response: false,
            result_code: ResultCode::NOERROR,
            checking_disabled: false,
            authenticated_data: false,
            z: false,
            recursion_available: false,
            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;

        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.operation_code = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;
        self.result_code = ResultCode::from(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authenticated_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;
        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }

    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.operation_code << 3)
                | ((self.response as u8) << 7) as u8,
        )?;

        buffer.write_u8(
            (self.result_code as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authenticated_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
    NS,
    CNAME,
    MX,
    AAAA,
}

impl From<u16> for QueryType {
    fn from(num: u16) -> Self {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

impl Into<u16> for QueryType {
    fn into(self) -> u16 {
        match self {
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 18,
            QueryType::UNKNOWN(num) => num,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub query_type: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, query_type: QueryType) -> Self {
        Self { name, query_type }
    }

    fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_query_name(&mut self.name)?;
        self.query_type = QueryType::from(buffer.read_u16()?);
        let _ = buffer.read_u16()?;

        Ok(())
    }

    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_query_name(&self.name)?;
        let query_type = self.query_type.into();
        buffer.write_u16(query_type)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        query_type: u16,
        len: u16,
        ttl: u32,
    },
    A {
        domain: String,
        address: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    AAAA {
        domain: String,
        address: Ipv6Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    fn read(buffer: &mut BytePacketBuffer) -> Result<Self> {
        let mut domain = String::new();

        buffer.read_query_name(&mut domain)?;

        let query_type = buffer.read_u16()?;
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let len = buffer.read_u16()?;

        match QueryType::from(query_type) {
            QueryType::A => {
                let raw_address = buffer.read_u32()?;
                let address = Ipv4Addr::new(
                    ((raw_address >> 24) & 0xFF) as u8,
                    ((raw_address >> 16) & 0xFF) as u8,
                    ((raw_address >> 8) & 0xFF) as u8,
                    ((raw_address >> 0) & 0xFF) as u8,
                );

                let result = DnsRecord::A {
                    domain,
                    address,
                    ttl,
                };

                Ok(result)
            }
            QueryType::AAAA => {
                let raw_address1 = buffer.read_u32()?;
                let raw_address2 = buffer.read_u32()?;
                let raw_address3 = buffer.read_u32()?;
                let raw_address4 = buffer.read_u32()?;
                let address = Ipv6Addr::new(
                    ((raw_address1 >> 16) & 0xFFFF) as u16,
                    ((raw_address1 >> 0) & 0xFFFF) as u16,
                    ((raw_address2 >> 16) & 0xFFFF) as u16,
                    ((raw_address2 >> 0) & 0xFFFF) as u16,
                    ((raw_address3 >> 16) & 0xFFFF) as u16,
                    ((raw_address3 >> 0) & 0xFFFF) as u16,
                    ((raw_address4 >> 16) & 0xFFFF) as u16,
                    ((raw_address4 >> 0) & 0xFFFF) as u16,
                );

                let result = DnsRecord::AAAA {
                    domain,
                    address,
                    ttl,
                };

                Ok(result)
            }
            QueryType::NS => {
                let mut host = String::new();
                buffer.read_query_name(&mut host)?;

                let result = DnsRecord::NS { domain, host, ttl };

                Ok(result)
            }
            QueryType::CNAME => {
                let mut host = String::new();
                buffer.read_query_name(&mut host)?;

                let result = DnsRecord::CNAME { domain, host, ttl };

                Ok(result)
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut host = String::new();
                buffer.read_query_name(&mut host)?;

                let result = DnsRecord::MX {
                    domain,
                    priority,
                    host,
                    ttl,
                };

                Ok(result)
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(len as usize)?;

                let result = DnsRecord::UNKNOWN {
                    domain,
                    query_type,
                    len,
                    ttl,
                };

                Ok(result)
            }
        }
    }

    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start = buffer.position;

        match *self {
            DnsRecord::A {
                ref domain,
                ref address,
                ttl,
            } => {
                buffer.write_query_name(domain)?;
                buffer.write_u16(QueryType::A.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = address.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_query_name(domain)?;
                buffer.write_u16(QueryType::NS.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let position = buffer.position;
                buffer.write_u16(0)?;

                buffer.write_query_name(host)?;

                let size = buffer.position - (position + 2);
                buffer.set_u16(position, size as u16)?;
            }
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_query_name(domain)?;
                buffer.write_u16(QueryType::CNAME.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let position = buffer.position;
                buffer.write_u16(0)?;

                buffer.write_query_name(host)?;

                let size = buffer.position - (position + 2);
                buffer.set_u16(position, size as u16)?;
            }
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_query_name(domain)?;
                buffer.write_u16(QueryType::MX.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let position = buffer.position;
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_query_name(host)?;

                let size = buffer.position - (position + 2);
                buffer.set_u16(position, size as u16)?;
            }
            DnsRecord::AAAA {
                ref domain,
                ref address,
                ttl,
            } => {
                buffer.write_query_name(domain)?;
                buffer.write_u16(QueryType::AAAA.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &address.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.position - start)
    }
}

#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> Self {
        Self {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<Self> {
        let mut result = DnsPacket::new();

        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let answer = DnsRecord::read(buffer)?;
            result.answers.push(answer);
        }

        for _ in 0..result.header.authoritative_entries {
            let authority = DnsRecord::read(buffer)?;
            result.authorities.push(authority);
        }

        for _ in 0..result.header.resource_entries {
            let resource = DnsRecord::read(buffer)?;
            result.resources.push(resource);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }

        for answer in &self.answers {
            answer.write(buffer)?;
        }

        for authority in &self.authorities {
            authority.write(buffer)?;
        }

        for resource in &self.resources {
            resource.write(buffer)?;
        }

        Ok(())
    }
}
