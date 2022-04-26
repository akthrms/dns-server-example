use std::convert::From;
use std::net::{Ipv4Addr, UdpSocket};

type Error = Box<dyn std::error::Error>;

type Result<T> = std::result::Result<T, Error>;

struct BytePacketBuffer {
    buffer: [u8; 512],
    position: usize,
}

impl BytePacketBuffer {
    fn new() -> Self {
        Self {
            buffer: [0; 512],
            position: 0,
        }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.position += steps;
        Ok(())
    }

    fn seek(&mut self, position: usize) -> Result<()> {
        self.position = position;
        Ok(())
    }

    fn read(&mut self) -> Result<u8> {
        if self.position >= 512 {
            return Err("end of buffer".into());
        }

        let result = self.buffer[self.position];
        self.position += 1;
        Ok(result)
    }

    fn get(&self, position: usize) -> Result<u8> {
        if position >= 512 {
            return Err("end of buffer".into());
        }

        let result = self.buffer[position];
        Ok(result)
    }

    fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err("end of buffer".into());
        }

        let result = &self.buffer[start..len + start];
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

    fn read_query_name(&mut self, out: &mut String) -> Result<()> {
        let mut position = self.position();

        let mut jumped = false;
        let mut jumped_cnt = 0;
        let max_jumped_cnt = 5;

        let mut delimiter = "";

        loop {
            if jumped_cnt > max_jumped_cnt {
                return Err(format!("limit of {} jumps exceeded", max_jumped_cnt).into());
            }

            let len = self.get(position)?;

            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(position + 2)?;
                }

                let b2 = self.get(position + 1)? as u16;
                let offset = ((len as u16) ^ 0xC0) << 8 | b2;
                position = offset as usize;

                jumped = true;
                jumped_cnt += 1;
            } else {
                position += 1;

                if len == 0 {
                    break;
                }

                out.push_str(delimiter);

                let buffer = self.get_range(position, len as usize)?;
                out.push_str(&String::from_utf8_lossy(buffer).to_lowercase());

                delimiter = ".";

                position += len as usize;
            }
        }

        if !jumped {
            self.seek(position)?;
        }

        Ok(())
    }

    fn write(&mut self, byte: u8) -> Result<()> {
        if self.position >= 512 {
            return Err("end of buffer".into());
        }

        self.buffer[self.position] = byte;
        self.position += 1;
        Ok(())
    }

    fn write_u8(&mut self, byte: u8) -> Result<()> {
        self.write(byte)?;
        Ok(())
    }

    fn write_u16(&mut self, byte: u16) -> Result<()> {
        self.write((byte >> 8) as u8)?;
        self.write(((byte >> 0) & 0xFF) as u8)?;
        Ok(())
    }

    fn write_u32(&mut self, byte: u32) -> Result<()> {
        self.write(((byte >> 24) & 0xFF) as u8)?;
        self.write(((byte >> 16) & 0xFF) as u8)?;
        self.write(((byte >> 8) & 0xFF) as u8)?;
        self.write(((byte >> 0) & 0xFF) as u8)?;
        Ok(())
    }

    fn write_query_name(&mut self, query_name: &str) -> Result<()> {
        for label in query_name.split(".") {
            let len = label.len();

            if len > 0x34 {
                return Err("single label exceeds 63 characters of length".into());
            }

            self.write_u8(len as u8)?;

            for byte in label.as_bytes() {
                self.write_u8(*byte)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResultCode {
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
struct DnsHeader {
    id: u16,
    recursion_desired: bool,
    truncated_message: bool,
    authoritative_answer: bool,
    operation_code: u8,
    response: bool,
    result_code: ResultCode,
    checking_disabled: bool,
    authenticated_data: bool,
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
enum QueryType {
    UNKNOWN(u16),
    A,
}

impl From<u16> for QueryType {
    fn from(num: u16) -> Self {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

impl Into<u16> for QueryType {
    fn into(self) -> u16 {
        match self {
            QueryType::A => 1,
            QueryType::UNKNOWN(num) => num,
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
enum DnsRecord {
    UNKNOWN {
        domain: String,
        query_type: u16,
        data_len: u16,
        ttl: u32,
    },
    A {
        domain: String,
        address: Ipv4Addr,
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
        let data_len = buffer.read_u16()?;

        match QueryType::from(query_type) {
            QueryType::A => {
                let raw_address = buffer.read_u32()?;
                let address = Ipv4Addr::new(
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
                    query_type,
                    data_len,
                    ttl,
                })
            }
        }
    }

    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start = buffer.position();

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
            DnsRecord::UNKNOWN { .. } => {
                println!("skipping record: {:?}", self);
            }
        }

        Ok(buffer.position() - start)
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

    fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }

        for record in &self.answers {
            record.write(buffer)?;
        }

        for record in &self.authorities {
            record.write(buffer)?;
        }

        for record in &self.resources {
            record.write(buffer)?;
        }

        Ok(())
    }
}

fn main() -> Result<()> {
    let query_name = "google.com";
    let query_type = QueryType::A;

    let server = ("8.8.8.8", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(query_name.to_string(), query_type));

    let mut request = BytePacketBuffer::new();

    packet.write(&mut request)?;

    socket.send_to(&request.buffer[0..request.position], server)?;

    let mut response = BytePacketBuffer::new();
    socket.recv_from(&mut response.buffer)?;

    let packet = DnsPacket::from_buffer(&mut response)?;

    println!("{:#?}", packet.header);

    for question in packet.questions {
        println!("{:#?}", question);
    }
    for record in packet.answers {
        println!("{:#?}", record);
    }
    for record in packet.authorities {
        println!("{:#?}", record);
    }
    for record in packet.resources {
        println!("{:#?}", record);
    }

    Ok(())
}
