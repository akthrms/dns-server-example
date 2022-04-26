use std::{fs::File, io::Read};

type Error = Box<dyn std::error::Error>;

type Result<T> = std::result::Result<T, Error>;

struct BytePacketBuffer {
    buf: [u8; 512],
    pos: usize,
}

impl BytePacketBuffer {
    fn new() -> Self {
        Self {
            buf: [0; 512],
            pos: 0,
        }
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;
        Ok(())
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }

    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("end of buffer".into());
        }

        let result = self.buf[self.pos];
        self.pos += 1;
        Ok(result)
    }

    fn get(&self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err("end of buffer".into());
        }

        let result = self.buf[pos];
        Ok(result)
    }

    fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err("end of buffer".into());
        }

        let result = &self.buf[start..len + start];
        Ok(result)
    }

    fn read_u16(&mut self) -> Result<u16> {
        let result = (self.read()? as u16) << 8 | (self.read()? as u16) << 0;
        Ok(result)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let result = (self.read()? as u32) << 24
            | (self.read()? as u32) << 16
            | (self.read()? as u32) << 8
            | (self.read()? as u32) << 0;
        Ok(result)
    }

    fn read_qname(&mut self, out: &mut String) -> Result<()> {
        let mut pos = self.pos();

        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        let mut delim = "";

        loop {
            if jumps_performed > max_jumps {
                return Err(format!("limit of {} jumps exceeded", max_jumps).into());
            }

            let len = self.get(pos)?;

            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(pos + 2)?;
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = ((len as u16) ^ 0xC0) << 8 | b2;
                pos = offset as usize;

                jumped = true;
                jumps_performed += 1;
            } else {
                pos += 1;

                if len == 0 {
                    break;
                }

                out.push_str(delim);

                let buffer = self.get_range(pos, len as usize)?;
                out.push_str(&String::from_utf8_lossy(buffer).to_lowercase());

                delim = ".";

                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl std::convert::From<u8> for ResultCode {
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
struct DnsHeader {
    id: u16,
    recursion_desired: bool,
    truncated_message: bool,
    authoritative_answer: bool,
    op_code: u8,
    response: bool,
    result_code: ResultCode,
    checking_disabled: bool,
    authed_data: bool,
    z: bool,
    recursion_available: bool,
    questions: u16,
    answers: u16,
    authoritative_entries: u16,
    resource_entries: u16,
}

impl DnsHeader {
    fn new() -> Self {
        Self {
            id: 0,
            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            op_code: 0,
            response: false,
            result_code: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
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
        self.op_code = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.result_code = ResultCode::from(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum QueryType {
    UNKNOWN(u16),
    A,
}

impl std::convert::From<u16> for QueryType {
    fn from(num: u16) -> Self {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsQuestion {
    name: String,
    query_type: QueryType,
}

impl DnsQuestion {
    fn new(name: String, query_type: QueryType) -> Self {
        Self { name, query_type }
    }

    fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.query_type = QueryType::from(buffer.read_u16()?);
        let _ = buffer.read_u16()?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum DnsRecord {
    UNKNOWN {
        domain: String,
        query_type: u16,
        data_len: u16,
        ttl: u32,
    },
    A {
        domain: String,
        address: std::net::Ipv4Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    fn read(buffer: &mut BytePacketBuffer) -> Result<Self> {
        let mut domain = String::new();

        buffer.read_qname(&mut domain)?;

        let qname_num = buffer.read_u16()?;
        let qtype = QueryType::from(qname_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_address = buffer.read_u32()?;
                let address = std::net::Ipv4Addr::new(
                    ((raw_address >> 24) & 0xFF) as u8,
                    ((raw_address >> 16) & 0xFF) as u8,
                    ((raw_address >> 8) & 0xFF) as u8,
                    ((raw_address >> 0) & 0xFF) as u8,
                );

                Ok(DnsRecord::A {
                    domain,
                    address,
                    ttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::UNKNOWN {
                    domain,
                    query_type: qname_num,
                    data_len,
                    ttl,
                })
            }
        }
    }
}

#[derive(Debug, Clone)]
struct DnsPacket {
    header: DnsHeader,
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsRecord>,
    authorities: Vec<DnsRecord>,
    resources: Vec<DnsRecord>,
}

impl DnsPacket {
    fn new() -> Self {
        Self {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<Self> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let record = DnsRecord::read(buffer)?;
            result.answers.push(record);
        }

        for _ in 0..result.header.authoritative_entries {
            let record = DnsRecord::read(buffer)?;
            result.authorities.push(record);
        }

        for _ in 0..result.header.resource_entries {
            let record = DnsRecord::read(buffer)?;
            result.resources.push(record);
        }

        Ok(result)
    }
}

fn main() -> Result<()> {
    let mut f = File::open("response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();
    f.read(&mut buffer.buf)?;

    let packet = DnsPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
