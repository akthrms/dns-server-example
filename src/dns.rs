use crate::packet::BytePacketBuffer;
use crate::utils::Result;
use log::debug;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    /// no error condition
    NOERROR,
    /// format error
    FORMERR,
    /// server failure
    SERVFAIL,
    /// name error
    NXDOMAIN,
    /// not implemented
    NOTIMP,
    /// refused
    REFUSED,
}

impl From<u8> for ResponseCode {
    fn from(num: u8) -> Self {
        match num {
            1 => ResponseCode::FORMERR,
            2 => ResponseCode::SERVFAIL,
            3 => ResponseCode::NXDOMAIN,
            4 => ResponseCode::NOTIMP,
            5 => ResponseCode::REFUSED,
            _ => ResponseCode::NOERROR,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Header {
    /// identifier assigned by the program that generates any kind of query
    pub id: u16,
    /// recursion desired
    pub rd: bool,
    /// truncation
    pub tc: bool,
    /// authoritative answer
    pub aa: bool,
    /// specifies kind of query in this message
    pub opcode: u8,
    /// response
    pub response: bool,
    /// response code
    pub rcode: ResponseCode,
    /// checking disabled
    pub cd: bool,
    /// authenticated Data
    pub ad: bool,
    /// reserved for future use
    pub z: bool,
    /// recursion Available
    pub ra: bool,
    /// the number of entries in the question section
    pub qdcount: u16,
    /// the number of resource records in the answer section
    pub ancount: u16,
    /// the number of name server resource records in the authority records section
    pub nscount: u16,
    /// the number of resource records in the additional records section
    pub arcount: u16,
}

impl Header {
    fn new() -> Self {
        Self {
            id: 0,
            rd: false,
            tc: false,
            aa: false,
            opcode: 0,
            response: false,
            rcode: ResponseCode::NOERROR,
            cd: false,
            ad: false,
            z: false,
            ra: false,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;

        self.rd = (a & (1 << 0)) > 0;
        self.tc = (a & (1 << 1)) > 0;
        self.aa = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;
        self.rcode = ResponseCode::from(b & 0x0F);
        self.cd = (b & (1 << 4)) > 0;
        self.ad = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.ra = (b & (1 << 7)) > 0;
        self.qdcount = buffer.read_u16()?;
        self.ancount = buffer.read_u16()?;
        self.nscount = buffer.read_u16()?;
        self.arcount = buffer.read_u16()?;

        Ok(())
    }

    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.rd as u8)
                | ((self.tc as u8) << 1)
                | ((self.aa as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7) as u8,
        )?;

        buffer.write_u8(
            (self.rcode as u8)
                | ((self.cd as u8) << 4)
                | ((self.ad as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.ra as u8) << 7),
        )?;

        buffer.write_u16(self.qdcount)?;
        buffer.write_u16(self.ancount)?;
        buffer.write_u16(self.nscount)?;
        buffer.write_u16(self.arcount)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueryType {
    /// 1 a host address
    A,
    /// 2 an authoritative name server
    NS,
    /// 5 the canonical name for an alias
    CNAME,
    /// 15 mail exchange
    MX,
    /// 28 a host address (IPv6 address)
    AAAA,
    /// unknown
    UNKNOWN(u16),
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
pub struct Question {
    pub qname: String,
    pub qtype: QueryType,
}

impl Question {
    pub fn new(qname: String, qtype: QueryType) -> Self {
        Self { qname, qtype }
    }

    fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.qname)?;
        self.qtype = QueryType::from(buffer.read_u16()?);
        let _ = buffer.read_u16()?;

        Ok(())
    }

    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.qname)?;
        let qtype = self.qtype.into();
        buffer.write_u16(qtype)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Record {
    /// a host address
    A {
        domain: String,
        address: Ipv4Addr,
        ttl: u32,
    },
    /// an authoritative name server
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    /// the canonical name for an alias
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    /// mail exchange
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    /// a host address (IPv6 address)
    AAAA {
        domain: String,
        address: Ipv6Addr,
        ttl: u32,
    },
    /// unknown
    UNKNOWN {
        domain: String,
        qtype: u16,
        len: u16,
        ttl: u32,
    },
}

impl Record {
    fn read(buffer: &mut BytePacketBuffer) -> Result<Self> {
        let mut domain = String::new();

        buffer.read_qname(&mut domain)?;

        let qtype = buffer.read_u16()?;
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let len = buffer.read_u16()?;

        match QueryType::from(qtype) {
            QueryType::A => {
                let raw_address = buffer.read_u32()?;
                let address = Ipv4Addr::new(
                    ((raw_address >> 24) & 0xFF) as u8,
                    ((raw_address >> 16) & 0xFF) as u8,
                    ((raw_address >> 8) & 0xFF) as u8,
                    ((raw_address >> 0) & 0xFF) as u8,
                );

                Ok(Record::A {
                    domain,
                    address,
                    ttl,
                })
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

                Ok(Record::AAAA {
                    domain,
                    address,
                    ttl,
                })
            }
            QueryType::NS => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(Record::NS { domain, host, ttl })
            }
            QueryType::CNAME => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(Record::CNAME { domain, host, ttl })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(Record::MX {
                    domain,
                    priority,
                    host,
                    ttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(len as usize)?;

                Ok(Record::UNKNOWN {
                    domain,
                    qtype,
                    len,
                    ttl,
                })
            }
        }
    }

    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start = buffer.position;

        match *self {
            Record::A {
                ref domain,
                ref address,
                ttl,
            } => {
                buffer.write_qname(domain)?;
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
            Record::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let position = buffer.position;

                buffer.write_u16(0)?;
                buffer.write_qname(host)?;

                let size = buffer.position - (position + 2);
                buffer.set_u16(position, size as u16)?;
            }
            Record::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let position = buffer.position;

                buffer.write_u16(0)?;
                buffer.write_qname(host)?;

                let size = buffer.position - (position + 2);
                buffer.set_u16(position, size as u16)?;
            }
            Record::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let position = buffer.position;

                buffer.write_u16(0)?;
                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.position - (position + 2);
                buffer.set_u16(position, size as u16)?;
            }
            Record::AAAA {
                ref domain,
                ref address,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &address.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            Record::UNKNOWN { .. } => {
                debug!("skipping record: {:?}", self);
            }
        }

        Ok(buffer.position - start)
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    /// header
    pub header: Header,
    /// the question for the name server
    pub questions: Vec<Question>,
    /// resource records answering the question
    pub answers: Vec<Record>,
    /// resource records pointing toward an authority
    pub authorities: Vec<Record>,
    /// resource records holding additional information
    pub additions: Vec<Record>,
}

impl Packet {
    pub fn new() -> Self {
        Self {
            header: Header::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additions: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<Self> {
        let mut result = Packet::new();

        result.header.read(buffer)?;

        for _ in 0..result.header.qdcount {
            let mut question = Question::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.ancount {
            result.answers.push(Record::read(buffer)?);
        }

        for _ in 0..result.header.nscount {
            result.authorities.push(Record::read(buffer)?);
        }

        for _ in 0..result.header.arcount {
            result.additions.push(Record::read(buffer)?);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.qdcount = self.questions.len() as u16;
        self.header.ancount = self.answers.len() as u16;
        self.header.nscount = self.authorities.len() as u16;
        self.header.arcount = self.additions.len() as u16;

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

        for addition in &self.additions {
            addition.write(buffer)?;
        }

        Ok(())
    }

    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers.iter().find_map(|answer| match answer {
            Record::A { address, .. } => Some(*address),
            _ => None,
        })
    }

    pub fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            .filter_map(|authority| match authority {
                Record::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            .filter(|(domain, _)| qname.ends_with(*domain))
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_ns(qname)
            .flat_map(|(_, host)| {
                self.additions
                    .iter()
                    .filter_map(move |addition| match addition {
                        Record::A {
                            domain, address, ..
                        } if domain == host => Some(address),
                        _ => None,
                    })
            })
            .map(|address| *address)
            .next()
    }

    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns(qname).map(|(_, host)| host).next()
    }
}
