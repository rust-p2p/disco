use std::io::{Read, Result, Write};
use std::net::{TcpListener, TcpStream};

fn handle_stream(mut stream: TcpStream) -> Result<()> {
    let mut buf = [0u8; 128];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        println!("read {}", n);
        stream.write_all(&buf[0..n])?;
        println!("write {}", n);
    }
}

fn main() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8000")?;
    println!("listening at 127.0.0.1:8000");

    for stream in listener.incoming() {
        println!("incoming");
        handle_stream(stream?)?;
        println!("closed");
    }

    Ok(())
}
