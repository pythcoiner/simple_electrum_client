pub(crate) mod ssl_client;
pub(crate) mod tcp_client;

use std::{net, time::Duration};

use self::{ssl_client::SslClient, tcp_client::TcpClient};

// Using a 1 byte seek buffer
pub const PEEK_BUFFER_SIZE: usize = 10;

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

    pub fn read_timeout(mut self, timeout: Option<Duration>) -> Self {
        match &mut self {
            Client::None => {}
            Client::Tcp(c) => c.read_timeout = timeout,
            Client::Ssl(c) => c.read_timeout = timeout,
        }
        self
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<(), Error> {
        match self {
            Client::None => Err(Error::NotConfigured),
            Client::Tcp(c) => c.set_read_timeout(timeout),
            Client::Ssl(c) => c.set_read_timeout(timeout),
        }
    }

    pub fn write_timeout(mut self, timeout: Option<Duration>) -> Self {
        match &mut self {
            Client::None => {}
            Client::Tcp(c) => c.write_timeout = timeout,
            Client::Ssl(c) => c.write_timeout = timeout,
        }
        self
    }

    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> Result<(), Error> {
        match self {
            Client::None => Err(Error::NotConfigured),
            Client::Tcp(c) => c.set_write_timeout(timeout),
            Client::Ssl(c) => c.set_write_timeout(timeout),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, thread, time::Instant};

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
        let _ = client.recv().unwrap();

        // non blocking recv
        client.send("ping");
        thread::sleep(Duration::from_secs(1));
        assert!(client.try_recv().unwrap().is_some());
        assert!(client.try_recv().unwrap().is_none());

        client.close().unwrap();
    }

    #[test]
    fn ssl_client_wo_certificate() {
        let (url, port) = split_url(ssl_local_address());
        let mut client = Client::new().ssl(&url, port);
        assert!(client.try_connect().is_err());
        let mut client = client.verif_certificate(false);
        client.connect();

        // blocking recv
        client.send("ping");
        let _ = client.recv().unwrap();

        // non blocking recv
        client.send("ping");
        thread::sleep(Duration::from_secs(1));
        assert!(client.try_recv().unwrap().is_some());
        assert!(client.try_recv().unwrap().is_none());

        client.close().unwrap();
    }

    #[test]
    fn ssl_client_with_certificate() {
        let (url, port) = split_url(ssl_acinq());
        let mut client = Client::new_ssl(&url, port);
        client.connect();
        client.send("ping");
        let _ = client.recv().unwrap();
        client.close().unwrap();
    }

    #[test]
    fn ssl_maybe() {
        let (url, port) = split_url(tcp_local_address());
        let mut client = Client::new_ssl_maybe(&url, port, false);
        client.connect();
        client.send("ping");
        let _ = client.recv().unwrap();
        client.close().unwrap();

        let (url, port) = split_url(ssl_local_address());
        let client = Client::new_ssl_maybe(&url, port, true);
        let mut client = client.verif_certificate(false);
        client.connect();
        client.send("ping");
        let _ = client.recv().unwrap();
        client.close().unwrap();
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

    fn timeout_template(url: &str, port: u16, ssl: bool) {
        let mut client = Client::new_ssl_maybe(url, port, ssl)
            .verif_certificate(false)
            .read_timeout(Some(Duration::from_millis(100)));
        client.connect();
        let start = Instant::now();
        let resp = client.recv();
        let duration = (Instant::now() - start).as_millis();
        assert!(duration > 100);
        assert!(duration < 120);
        assert_eq!(
            format!("{resp:?}"),
            r#"Err(TcpStream(Os { code: 11, kind: WouldBlock, message: "Resource temporarily unavailable" }))"#
        );

        let mut client = Client::new_ssl_maybe(url, port, ssl).verif_certificate(false);
        client.connect();
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let start = Instant::now();
        let resp = client.recv();
        let duration = (Instant::now() - start).as_millis();
        assert!(duration > 500);
        assert!(duration < 600);
        assert_eq!(
            format!("{resp:?}"),
            r#"Err(TcpStream(Os { code: 11, kind: WouldBlock, message: "Resource temporarily unavailable" }))"#
        );
    }

    #[test]
    fn timeout_tcp() {
        let (url, port) = split_url(tcp_local_address());
        timeout_template(&url, port, false);
    }

    #[test]
    fn timeout_ssl() {
        let (url, port) = split_url(ssl_local_address());
        timeout_template(&url, port, true);
    }
}
