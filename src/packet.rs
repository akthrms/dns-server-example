use crate::utils::Result;

const LIMIT_OF_BUFFER: usize = 512;

pub struct BytePacketBuffer {
    pub buffer: [u8; 512],
    pub position: usize,
}

impl BytePacketBuffer {
    pub fn new() -> Self {
        Self {
            buffer: [0; 512],
            position: 0,
        }
    }

    pub fn step(&mut self, steps: usize) -> Result<()> {
        self.position += steps;

        Ok(())
    }

    fn seek(&mut self, position: usize) -> Result<()> {
        self.position = position;

        Ok(())
    }

    fn read(&mut self) -> Result<u8> {
        if self.position >= LIMIT_OF_BUFFER {
            return Err("End of buffer".into());
        }

        let result = self.buffer[self.position];
        self.position += 1;

        Ok(result)
    }

    fn get(&self, position: usize) -> Result<u8> {
        if position >= LIMIT_OF_BUFFER {
            return Err("End of buffer".into());
        }

        let result = self.buffer[position];

        Ok(result)
    }

    pub fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= LIMIT_OF_BUFFER {
            return Err("End of buffer".into());
        }

        let result = &self.buffer[start..len + start];

        Ok(result)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let result = (self.read()? as u16) << 8 | (self.read()? as u16) << 0;

        Ok(result)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let result = (self.read()? as u32) << 24
            | (self.read()? as u32) << 16
            | (self.read()? as u32) << 8
            | (self.read()? as u32) << 0;

        Ok(result)
    }

    pub fn read_query_name(&mut self, out: &mut String) -> Result<()> {
        let mut position = self.position;

        let mut jumped = false;
        let mut jumped_cnt = 0;
        let max_jumped_cnt = 5;

        let mut delimiter = "";

        loop {
            if jumped_cnt > max_jumped_cnt {
                return Err(format!("Limit of {} jumps exceeded", max_jumped_cnt).into());
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
        if self.position >= LIMIT_OF_BUFFER {
            return Err("End of buffer".into());
        }

        self.buffer[self.position] = byte;
        self.position += 1;

        Ok(())
    }

    pub fn write_u8(&mut self, byte: u8) -> Result<()> {
        self.write(byte)?;

        Ok(())
    }

    pub fn write_u16(&mut self, byte: u16) -> Result<()> {
        self.write(((byte >> 8) & 0xFF) as u8)?;
        self.write(((byte >> 0) & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_u32(&mut self, byte: u32) -> Result<()> {
        self.write(((byte >> 24) & 0xFF) as u8)?;
        self.write(((byte >> 16) & 0xFF) as u8)?;
        self.write(((byte >> 8) & 0xFF) as u8)?;
        self.write(((byte >> 0) & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_query_name(&mut self, query_name: &str) -> Result<()> {
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

    fn set(&mut self, position: usize, byte: u8) -> Result<()> {
        self.buffer[position] = byte;

        Ok(())
    }

    pub fn set_u16(&mut self, position: usize, byte: u16) -> Result<()> {
        self.set(position, (byte >> 8) as u8)?;
        self.set(position + 1, (byte & 0xFF) as u8)?;

        Ok(())
    }
}
