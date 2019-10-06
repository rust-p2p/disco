use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;

fn main() -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect("127.0.0.1:8000")?;

    stream.write(b"hello world")?;

    let mut buf = vec![0u8; 11];
    stream.read_exact(&mut buf)?;

    let res = std::str::from_utf8(&buf)?;
    println!("received: {}", res);

    Ok(())
}
