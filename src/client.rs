use std::{
    clone,
    io::{self, BufRead, BufReader, Read, Write},
    iter,
    net::{self, TcpStream as StdTcpStream},
    sync::{mpsc, Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use bitcoin::hex::DisplayHex;
use openssl::ssl::{self, SslConnector, SslMethod, SslVerifyMode};

// Using a 1 byte seek buffer
const PEEK_BUFFER_SIZE: usize = 1000;

#[derive(Debug)]
pub enum Error {
    TcpStream(std::io::Error),
    SslStream(openssl::ssl::HandshakeError<net::TcpStream>),
    SslPeek,
    Mutex,
    SslConnector(std::io::Error),
    AlreadyConnected,
    NotConnected,
    NotConfigured,
    ShutDown,
    SetNonBlocking,
    SetBlocking,
}

#[derive(Debug, Default, Clone)]
pub enum Client {
    #[default]
    None,
    Tcp(TcpClient),
    Ssl(SslClient),
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl Client {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tcp(self, url: &str, port: u16) -> Self {
        Self::new_tcp(url, port)
    }

    pub fn new_tcp(url: &str, port: u16) -> Self {
        Self::Tcp(TcpClient::default().url(url).port(port))
    }

    pub fn ssl(self, url: &str, port: u16) -> Self {
        Self::new_ssl(url, port)
    }

    pub fn new_ssl(url: &str, port: u16) -> Self {
        Self::Ssl(SslClient::default().url(url).port(port))
    }

    pub fn new_ssl_maybe(url: &str, port: u16, ssl: bool) -> Self {
        match ssl {
            true => Self::new_ssl(url, port),
            false => Self::new_tcp(url, port),
        }
    }

    pub fn verif_certificate(mut self, verif: bool) -> Self {
        let connected = self.is_connected();
        if let (
            Self::Ssl(SslClient {
                verif_certificate, ..
            }),
            false,
        ) = (&mut self, connected)
        {
            *verif_certificate = verif;
        }
        self
    }

    pub fn connect(&mut self) {
        self.try_connect().unwrap()
    }

    pub fn is_connected(&self) -> bool {
        match self {
            Client::None => false,
            Client::Tcp(c) => c.is_connected(),
            Client::Ssl(c) => c.is_connected(),
        }
    }

    pub fn try_connect(&mut self) -> Result<(), Error> {
        match self {
            Client::None => Err(Error::NotConfigured),
            Client::Tcp(c) => c.try_connect(),
            Client::Ssl(c) => c.try_connect(),
        }
    }

    pub fn send(&mut self, request: &str) {
        self.try_send(request).unwrap();
    }

    pub fn send_batch(&mut self, requests: Vec<&str>) {
        self.try_send_batch(requests).unwrap();
    }

    pub fn try_send(&mut self, request: &str) -> Result<(), Error> {
        match self {
            Client::None => Err(Error::NotConfigured),
            Client::Tcp(c) => {
                if let Some(stream) = c.stream.as_mut() {
                    let mut stream = stream.lock().map_err(|_| Error::Mutex)?;
                    TcpClient::send(&mut stream, request)
                } else {
                    Err(Error::NotConnected)
                }
            }
            Client::Ssl(c) => {
                if let Some(stream) = c.stream.as_mut() {
                    let mut stream = stream.lock().map_err(|_| Error::Mutex)?;
                    SslClient::send(&mut stream, request)
                } else {
                    Err(Error::NotConnected)
                }
            }
        }
    }

    pub fn try_send_batch(&mut self, requests: Vec<&str>) -> Result<(), Error> {
        // TODO: add a max batch size?
        for request in requests {
            self.try_send(request)?;
        }
        Ok(())
    }

    pub fn recv(&mut self) -> Result<String, Error> {
        match self {
            Client::None => Err(Error::NotConfigured),
            Client::Tcp(c) => {
                if let Some(stream) = c.stream.as_mut() {
                    let mut stream = stream.lock().map_err(|_| Error::Mutex)?;
                    TcpClient::read(&mut stream)
                } else {
                    Err(Error::NotConnected)
                }
            }
            Client::Ssl(c) => {
                if let Some(stream) = c.stream.as_mut() {
                    let mut stream = stream.lock().map_err(|_| Error::Mutex)?;
                    SslClient::read(&mut stream)
                } else {
                    Err(Error::NotConnected)
                }
            }
        }
    }

    pub fn try_recv(&mut self) -> Result<Option<String>, Error> {
        match self {
            Client::None => Err(Error::NotConfigured),
            Client::Tcp(c) => {
                if let Some(stream) = c.stream.as_mut() {
                    let mut stream = stream.lock().map_err(|_| Error::Mutex)?;
                    TcpClient::try_read(&mut stream)
                } else {
                    Err(Error::NotConnected)
                }
            }
            Client::Ssl(c) => {
                if let Some(stream) = c.stream.as_mut() {
                    let mut stream = stream.lock().map_err(|_| Error::Mutex)?;
                    SslClient::try_read(&mut stream)
                } else {
                    Err(Error::NotConnected)
                }
            }
        }
    }

    // // TODO: add a timeout
    // pub fn single_request(&mut self, request: &str) -> Result<String, Error> {
    //     if !self.is_connected() {
    //         self.try_connect()?;
    //         self.try_send(request)?;
    //         // FIXME: do not release the lock here
    //         let response = self.recv()?;
    //         self.close()?;
    //         Ok(response)
    //     } else {
    //         Err(Error::AlreadyConnected)
    //     }
    // }

    pub fn close(&mut self) -> Result<(), Error> {
        match self {
            Client::None => Ok(()),
            Client::Tcp(c) => c.close(),
            Client::Ssl(c) => c.close(),
        }
    }
}

type TcpStream = Arc<Mutex<net::TcpStream>>;

#[derive(Debug)]
pub struct TcpClient {
    url: String,
    port: u16,
    stream: Option<TcpStream>,
}

impl Clone for TcpClient {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            port: self.port,
            stream: self.stream.clone(),
        }
    }
}

#[allow(clippy::derivable_impls)]
impl Default for TcpClient {
    fn default() -> Self {
        Self {
            url: Default::default(),
            port: 50002,
            stream: None,
        }
    }
}

impl Drop for TcpClient {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl TcpClient {
    pub fn url(mut self, url: &str) -> Self {
        if !self.is_connected() {
            self.url = url.into();
        } else {
            log::error!("Cannot change url of a connected TcpClient!")
        }
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        if !self.is_connected() {
            self.port = port;
        } else {
            log::error!("Cannot change port of a connected TcpClient!")
        }
        self
    }

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    pub fn try_connect(&mut self) -> Result<(), Error> {
        let url = format!("{}:{}", self.url, self.port);
        let mut stream = net::TcpStream::connect(url).map_err(Error::TcpStream)?;
        // stream.set_nonblocking(true);
        if self.stream.is_none() {
            self.stream = Some(Arc::new(Mutex::new(stream)));
            Ok(())
        } else {
            Err(Error::AlreadyConnected)
        }
    }

    pub fn send(stream: &mut net::TcpStream, request: &str) -> Result<(), Error> {
        stream
            .write_all(request.as_bytes())
            .map_err(Error::TcpStream)?;
        // add a \n char for EOL
        stream.write_all(&[10]).map_err(Error::TcpStream)?;
        stream.flush().map_err(Error::TcpStream)?;
        Ok(())
    }

    fn raw_read(stream: &mut net::TcpStream, blocking: bool) -> Result<Option<String>, Error> {
        let mut peek_buffer = [0u8; PEEK_BUFFER_SIZE];

        // TcpStream.peek() if `nonblocking` is false
        stream
            .set_nonblocking(true)
            .map_err(|_| Error::SetNonBlocking)?;
        // If no data in the TcpStream receiving end, TcpStream.peek() will error
        let peek = stream.peek(&mut peek_buffer).ok();
        stream
            .set_nonblocking(false)
            .map_err(|_| Error::SetBlocking)?;

        // If blocking or data in the TcpStream receiving end
        if blocking || peek.is_some() {
            let mut response = String::new();
            let mut reader = BufReader::new(stream.try_clone().map_err(Error::TcpStream)?);
            reader.read_line(&mut response).map_err(Error::TcpStream)?;
            Ok(Some(response))
        } else {
            Ok(None)
        }
    }

    pub fn try_read(stream: &mut net::TcpStream) -> Result<Option<String>, Error> {
        Self::raw_read(stream, false)
    }

    pub fn read(stream: &mut net::TcpStream) -> Result<String, Error> {
        Ok(Self::raw_read(stream, true)?.expect("blocking"))
    }

    pub fn close(&mut self) -> Result<(), Error> {
        if let Some(stream) = self.stream.take() {
            stream
                .try_lock()
                .map_err(|_| Error::Mutex)?
                .shutdown(net::Shutdown::Both)
                .map_err(|_| Error::ShutDown)?;
            Ok(())
        } else {
            Err(Error::NotConnected)
        }
    }
}

type SslStream = Arc<Mutex<ssl::SslStream<net::TcpStream>>>;

#[derive(Debug)]
pub struct SslClient {
    url: String,
    port: u16,
    stream: Option<SslStream>,
    verif_certificate: bool,
}

impl Clone for SslClient {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            port: self.port,
            stream: self.stream.clone(),
            verif_certificate: self.verif_certificate,
        }
    }
}

impl Drop for SslClient {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl Default for SslClient {
    fn default() -> Self {
        Self {
            url: Default::default(),
            port: 50002,
            stream: None,
            verif_certificate: true,
        }
    }
}

impl SslClient {
    pub fn url(mut self, url: &str) -> Self {
        if !self.is_connected() {
            self.url = url.into();
        } else {
            log::error!("Cannot change url of a connected SslClient!")
        }
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        if !self.is_connected() {
            self.port = port;
        } else {
            log::error!("Cannot change port of a connected TcpClient!")
        }
        self
    }

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    pub fn try_connect(&mut self) -> Result<(), Error> {
        let url = format!("{}:{}", self.url, self.port);
        let mut ssl = SslConnector::builder(SslMethod::tls()).unwrap();
        // do not verify for self-signed certs
        if !self.verif_certificate {
            ssl.set_verify(SslVerifyMode::NONE);
        }
        let ssl = ssl.build();
        let stream = net::TcpStream::connect(url).map_err(Error::TcpStream)?;
        let stream = ssl.connect(&self.url, stream).map_err(Error::SslStream)?;
        let stream = Arc::new(Mutex::new(stream));
        let cloned = stream.clone();

        if self.stream.is_none() {
            self.stream = Some(stream);
            Ok(())
        } else {
            Err(Error::AlreadyConnected)
        }
    }

    pub fn send(stream: &mut ssl::SslStream<net::TcpStream>, request: &str) -> Result<(), Error> {
        stream
            .write_all(request.as_bytes())
            .map_err(Error::TcpStream)?;
        // add a \n char for EOL
        stream.write_all(&[10]).map_err(Error::TcpStream)?;
        stream.flush().map_err(Error::TcpStream)?;
        Ok(())
    }

    fn raw_read(
        stream: &mut ssl::SslStream<net::TcpStream>,
        blocking: bool,
    ) -> Result<Option<String>, Error> {
        let mut peek_buffer = [0u8; PEEK_BUFFER_SIZE];
        // SslStream will block if `nonblocking` is false
        stream
            .get_mut()
            .set_nonblocking(true)
            .map_err(|_| Error::SetNonBlocking)?;
        // SslStream.ssl_peek() will error if there is no data in the
        // stream receiving end
        let peek = stream.ssl_peek(&mut peek_buffer).ok();
        stream
            .get_mut()
            .set_nonblocking(false)
            .map_err(|_| Error::SetBlocking)?;

        // If blocking or data in the receiving end of the stream
        if blocking || peek.is_some() {
            let mut response = String::new();
            let mut reader = BufReader::new(stream);
            reader.read_line(&mut response).map_err(Error::TcpStream)?;
            Ok(Some(response))
        } else {
            Ok(None)
        }
    }

    pub fn try_read(stream: &mut ssl::SslStream<net::TcpStream>) -> Result<Option<String>, Error> {
        Self::raw_read(stream, false)
    }

    pub fn read(stream: &mut ssl::SslStream<net::TcpStream>) -> Result<String, Error> {
        Ok(Self::raw_read(stream, true)?.expect("blocking"))
    }

    pub fn close(&mut self) -> Result<(), Error> {
        if let Some(stream) = self.stream.take() {
            stream
                .try_lock()
                .map_err(|_| Error::Mutex)?
                .shutdown()
                .map_err(|_| Error::ShutDown)?;
            Ok(())
        } else {
            Err(Error::NotConnected)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{default, env, thread};

    use serde::de;

    use super::*;

    fn env_var(arg: &str, default: &str) -> String {
        if let Ok(value) = env::var(arg) {
            value
        } else {
            default.into()
        }
    }

    fn tcp_local_address() -> String {
        env_var("TCP_LOCAL_ADDRESS", "192.168.1.21:50003")
    }
    fn ssl_local_address() -> String {
        env_var("SSL_LOCAL_ADDRESS", "192.168.1.21:60002")
    }
    fn ssl_acinq() -> String {
        env_var("SSL_ACINQ_ADDRESS", "electrum.acinq.co:50002")
    }

    fn split_url(url: String) -> (String, u16) {
        let (url, port) = url.rsplit_once(':').unwrap();
        let port = port.parse::<u16>().unwrap();
        (url.to_string(), port)
    }

    #[test]
    fn tcp_client() {
        let (url, port) = split_url(tcp_local_address());
        let mut client = Client::new().tcp(&url, port);
        client.connect();

        // blocking recv
        client.send("ping");
        let response = client.recv().unwrap();

        // non blocking recv
        client.send("ping");
        thread::sleep(Duration::from_secs(1));
        assert!(client.try_recv().unwrap().is_some());
        assert!(client.try_recv().unwrap().is_none());

        client.close();
    }

    #[test]
    fn ssl_client_wo_certificate() {
        let (url, port) = split_url(ssl_local_address());
        let mut client = Client::new().ssl(&url, port);
        client.try_connect().is_err();
        let mut client = client.verif_certificate(false);
        client.connect();

        // blocking recv
        client.send("ping");
        let response = client.recv().unwrap();

        // non blocking recv
        client.send("ping");
        thread::sleep(Duration::from_secs(1));
        assert!(client.try_recv().unwrap().is_some());
        assert!(client.try_recv().unwrap().is_none());

        client.close();
    }

    #[test]
    fn ssl_client_with_certificate() {
        let (url, port) = split_url(ssl_acinq());
        let mut client = Client::new_ssl(&url, port);
        client.connect();
        client.send("ping");
        let response = client.recv().unwrap();
        client.close();
    }

    #[test]
    fn ssl_maybe() {
        let (url, port) = split_url(tcp_local_address());
        let mut client = Client::new_ssl_maybe(&url, port, false);
        client.connect();
        client.send("ping");
        let response = client.recv().unwrap();
        client.close();

        let (url, port) = split_url(ssl_local_address());
        let mut client = Client::new_ssl_maybe(&url, port, true);
        let mut client = client.verif_certificate(false);
        client.connect();
        client.send("ping");
        let response = client.recv().unwrap();
        client.close();
    }

    #[test]
    fn tcp_clone() {
        let (url, port) = split_url(tcp_local_address());
        let mut client = Client::new_ssl_maybe(&url, port, false);
        client.connect();

        let mut cloned = client.clone();

        client.send("ping");
        cloned.recv().unwrap();
    }
}
