use disco::{ReadError, SessionBuilder};
use std::io::{Error as IoError, Read, Write};
use std::net::{TcpListener, TcpStream};

#[derive(Debug)]
enum Error {
    Disco(ReadError),
    Io(IoError),
    Parse(std::str::Utf8Error),
}

impl From<ReadError> for Error {
    fn from(e: ReadError) -> Self {
        Self::Disco(e)
    }
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Self {
        Self::Io(e)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::Parse(e)
    }
}

fn send(stream: &mut TcpStream, buf: &[u8]) -> Result<(), Error> {
    let msg_len = buf.len() as u16;
    stream.write_all(&msg_len.to_be_bytes()[..])?;
    stream.write_all(buf)?;
    Ok(())
}

fn recv(stream: &mut TcpStream) -> Result<Vec<u8>, Error> {
    let mut msg_len_buf = [0u8; 2];
    stream.read_exact(&mut msg_len_buf)?;
    let msg_len = u16::from_be_bytes(msg_len_buf);
    let mut msg = vec![0u8; msg_len as usize];
    stream.read_exact(&mut msg[..])?;
    Ok(msg)
}

fn handle_stream(mut stream: TcpStream) -> Result<(), Error> {
    let mut session = SessionBuilder::new("NN").build_responder();
    while !session.is_handshake_finished() {
        let ct = recv(&mut stream)?;
        session.read_message(&ct)?;
        let ct = session.write_message(&[]);
        send(&mut stream, &ct)?;
    }
    let mut session = session.into_transport_mode();
    while let Ok(ct) = recv(&mut stream) {
        let pt = session.read_message(&ct)?;
        println!("client said: {}", std::str::from_utf8(&pt)?);
        let ct = session.write_message(&pt);
        send(&mut stream, &ct)?;
    }
    Ok(())
}

fn run_server() -> Result<(), Error> {
    let listener = TcpListener::bind("127.0.0.1:8000")?;
    println!("listening at 127.0.0.1:8000");

    for stream in listener.incoming() {
        if let Err(e) = handle_stream(stream?) {
            eprintln!("{:?}", e);
        }
    }

    Ok(())
}

fn run_client() -> Result<(), Error> {
    let mut stream = TcpStream::connect("127.0.0.1:8000")?;
    let mut session = SessionBuilder::new("NN").build_initiator();
    while !session.is_handshake_finished() {
        let ct = session.write_message(&[]);
        send(&mut stream, &ct)?;
        let ct = recv(&mut stream)?;
        session.read_message(&ct)?;
    }
    let mut session = session.into_transport_mode();

    let pt = b"hello world";
    let ct = session.write_message(&pt[..]);
    send(&mut stream, &ct)?;
    let ct = recv(&mut stream)?;
    let pt = session.read_message(&ct)?;
    println!("server said: {}", std::str::from_utf8(&pt)?);

    Ok(())
}

fn main() -> Result<(), Error> {
    let arg = std::env::args().nth(1);
    if let Some(arg) = arg {
        if arg == "--server" {
            return run_server();
        } else {
            eprintln!("Unknown arg. To run in server mode use --server.");
        }
    }
    run_client()
}
