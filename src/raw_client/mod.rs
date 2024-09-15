pub(crate) mod ssl_client;
pub(crate) mod tcp_client;

use std::{collections::HashMap, net, time::Duration};

use crate::electrum::{
    self,
    request::Request,
    response::{parse_str_response, Response},
};

use self::{ssl_client::SslClient, tcp_client::TcpClient};

// Using a 1 byte seek buffer
pub const PEEK_BUFFER_SIZE: usize = 10;

#[derive(Debug)]
pub enum Error {
    TcpStream(std::io::Error),
    SslStream(openssl::ssl::HandshakeError<net::TcpStream>),
    Electrum(electrum::Error),
    SslPeek,
    Mutex,
    SslConnector(std::io::Error),
    AlreadyConnected,
    NotConnected,
    NotConfigured,
    ShutDown,
    SetNonBlocking,
    SetBlocking,
    SerializeRequest,
    Batch,
}

impl From<electrum::Error> for Error {
    fn from(value: electrum::Error) -> Self {
        Error::Electrum(value)
    }
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

    pub fn send(&mut self, request: &Request) {
        self.try_send(request).unwrap();
    }

    pub fn send_str(&mut self, request: &str) {
        self.try_send_str(request).unwrap();
    }

    pub fn try_send_batch(&mut self, requests: Vec<&Request>) -> Result<(), Error> {
        let batch = serde_json::to_string(&requests).map_err(|_| Error::Batch)?;
        self.try_send_str(&batch)
    }

    pub fn try_send(&mut self, request: &Request) -> Result<(), Error> {
        let s = serde_json::to_string(request).map_err(|_| Error::SerializeRequest)?;
        self.try_send_str(&s)
    }

    pub fn try_send_str(&mut self, request: &str) -> Result<(), Error> {
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

    pub fn recv(&mut self, index: &HashMap<usize, Request>) -> Result<Vec<Response>, Error> {
        let raw = self.recv_str()?;
        Ok(parse_str_response(&raw, index)?)
    }

    pub fn recv_str(&mut self) -> Result<String, Error> {
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

    pub fn try_recv(
        &mut self,
        index: &HashMap<usize, Request>,
    ) -> Result<Option<Vec<Response>>, Error> {
        let raw = self.try_recv_str()?;
        if let Some(rr) = raw {
            Ok(Some(parse_str_response(&rr, index)?))
        } else {
            Ok(None)
        }
    }

    pub fn try_recv_str(&mut self) -> Result<Option<String>, Error> {
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
    use bitcoin::{hex::FromHex, OutPoint, Script};

    use crate::electrum::{
        request::Request,
        response::{
            BannerResponse, Header, HeaderNotification, HeaderResponse, Headers, HeadersResponse,
            PingResponse,
        },
    };

    use self::electrum::response::{
        SHSubscribeResponse, SHUnsubscribeResponse, TxGetResponse, TxGetResult, VersionResponse,
    };

    use super::*;
    use std::{env, str::FromStr, thread, time::Instant};

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

    fn tcp_client() -> Client {
        let (url, port) = split_url(tcp_local_address());
        Client::new().tcp(&url, port)
    }

    fn acinq_client() -> Client {
        let (url, port) = split_url(ssl_acinq());
        Client::new().ssl(&url, port)
    }

    #[test]
    fn tcp_client_send_recv() {
        let (url, port) = split_url(tcp_local_address());
        let mut client = Client::new().tcp(&url, port);
        client.connect();

        // blocking recv
        client.send_str("ping");
        let _ = client.recv_str().unwrap();

        // non blocking recv
        client.send_str("ping");
        thread::sleep(Duration::from_secs(1));
        assert!(client.try_recv_str().unwrap().is_some());
        assert!(client.try_recv_str().unwrap().is_none());

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
        client.send_str("ping");
        let _ = client.recv_str().unwrap();

        // non blocking recv
        client.send_str("ping");
        thread::sleep(Duration::from_secs(1));
        assert!(client.try_recv_str().unwrap().is_some());
        assert!(client.try_recv_str().unwrap().is_none());

        client.close().unwrap();
    }

    #[test]
    fn ssl_client_with_certificate() {
        let (url, port) = split_url(ssl_acinq());
        let mut client = Client::new_ssl(&url, port);
        client.connect();
        client.send_str("ping");
        let _ = client.recv_str().unwrap();
        client.close().unwrap();
    }

    #[test]
    fn ssl_maybe() {
        let (url, port) = split_url(tcp_local_address());
        let mut client = Client::new_ssl_maybe(&url, port, false);
        client.connect();
        client.send_str("ping");
        let _ = client.recv_str().unwrap();
        client.close().unwrap();

        let (url, port) = split_url(ssl_local_address());
        let client = Client::new_ssl_maybe(&url, port, true);
        let mut client = client.verif_certificate(false);
        client.connect();
        client.send_str("ping");
        let _ = client.recv_str().unwrap();
        client.close().unwrap();
    }

    #[test]
    fn tcp_clone() {
        let (url, port) = split_url(tcp_local_address());
        let mut client = Client::new_ssl_maybe(&url, port, false);
        client.connect();

        let mut cloned = client.clone();

        client.send_str("ping");
        cloned.recv_str().unwrap();
    }

    fn timeout_template(url: &str, port: u16, ssl: bool) {
        let mut client = Client::new_ssl_maybe(url, port, ssl)
            .verif_certificate(false)
            .read_timeout(Some(Duration::from_millis(100)));
        client.connect();
        let start = Instant::now();
        let resp = client.recv_str();
        let duration = (Instant::now() - start).as_millis();
        assert!(duration > 100);
        assert!(duration < 200);
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
        let resp = client.recv_str();
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

    fn request_response_match(request: Request, response: Response) {
        let mut client = tcp_client();
        client.connect();
        client.send(&request);
        let mut index = HashMap::new();
        index.insert(request.id, request);
        assert_eq!(client.recv(&index).unwrap()[0], response);
    }

    #[test]
    fn ping() {
        let request = Request::ping();
        let response = Response::Ping(PingResponse {
            id: 0,
            result: None,
        });
        request_response_match(request, response);
    }

    #[test]
    fn banner() {
        let request = Request::banner();
        let mut client = tcp_client();
        client.connect();
        client.send(&request);
        let mut index = HashMap::new();
        index.insert(request.id, request);
        matches!(
            client.recv(&index).unwrap()[0],
            Response::Banner(BannerResponse { id: 0, .. })
        );
    }

    #[test]
    fn block_header() {
        let mut client = tcp_client();
        client.connect();

        let request = Request::subscribe_headers();
        client.send(&request);
        let mut index = HashMap::new();
        index.insert(request.id, request.clone());

        // We get the chain tip w/ a Request.subscribe_header()
        // NOTE: there is no method to unsubscribe so during the test
        // we can receive an unintended header notification
        let response = client.recv(&index).unwrap();
        if let Response::HeaderNotification(HeaderNotification { id, header }) = &response[0] {
            assert_eq!(request.id, *id);
            let Header { height, .. } = header;
            let height = height - 10;

            // We can now not get a single header
            let request = Request::header(height);
            client.send(&request);
            index.insert(request.id, request);
            let response = client.recv(&index).unwrap();
            // TODO: handle unintended notification
            if let Response::Header(HeaderResponse { id, raw_header }) = &response[0] {
                assert_eq!(*id, 0);
                assert!(!raw_header.is_empty())
            } else {
                panic!("wrong response")
            }

            // Now get several headers
            let request = Request::headers(height, 5);
            client.send(&request);
            index.insert(request.id, request);
            let response = client.recv(&index).unwrap();
            // TODO: handle unintended notification
            if let Response::Headers(HeadersResponse {
                id,
                headers:
                    Headers {
                        count,
                        raw_headers,
                        max,
                    },
            }) = &response[0]
            {
                assert_eq!(*id, 0);
                assert_eq!(*count, 5);
                assert!(*max > 1);
                assert!(!raw_headers.is_empty())
            } else {
                panic!("wrong response")
            }
        } else {
            panic!("wrong response")
        }
    }

    #[test]
    fn test_version() {
        let mut client = tcp_client();
        client.connect();

        let request = Request::version("smart".into(), "1.4".into());
        client.send(&request);
        let mut index = HashMap::new();
        index.insert(request.id, request.clone());
        let response = client.recv(&index).unwrap();
        if let Response::Version(VersionResponse { id, .. }) = response[0] {
            assert_eq!(id, 0);
        } else {
            panic!("wrong response");
        }
    }

    #[test]
    fn tx_get() {
        let mut client = acinq_client();
        client.connect();

        let raw_outpoint = "e03a9a4b5c557f6ee3400a29ff1475d1df73e9cddb48c2391abdc391d8c1504a:0";
        let outpoint = OutPoint::from_str(raw_outpoint).unwrap();

        // get raw tx
        let request = Request::tx_get(outpoint.txid);
        client.send(&request);
        let mut index = HashMap::new();
        index.insert(request.id, request.clone());
        let response = client.recv(&index).unwrap();
        if let Response::TxGet(TxGetResponse {
            id,
            result: TxGetResult::Raw(raw_tx),
        }) = &response[0]
        {
            assert_eq!(*id, 0);
            assert!(!raw_tx.is_empty());
        } else {
            panic!("wrong response")
        }

        // get verbose tx
        let request = Request::tx_get_verbose(outpoint.txid);
        client.send(&request);
        let mut index = HashMap::new();
        index.insert(request.id, request.clone());
        let response = client.recv(&index).unwrap();
        if let Response::TxGet(TxGetResponse {
            id,
            result: TxGetResult::Verbose(tx),
        }) = &response[0]
        {
            assert_eq!(*id, 0);
            assert!(!tx.raw_tx.is_empty())
        } else {
            panic!("wrong response")
        }
    }

    #[test]
    fn sh_subscribe_unsubscribe() {
        let mut client = tcp_client();
        client.connect();

        let mut index = HashMap::new();

        let script = Script::from_bytes(&[0x00]);

        // unsubscribe w/o subscription we expect result==false
        let request = Request::unsubscribe_sh(script);
        client.send(&request);
        index.insert(request.id, request);
        let response = &client.recv(&index).unwrap()[0];
        if let Response::SHUnsubscribe(SHUnsubscribeResponse { id, result }) = response {
            assert_eq!(*id, 0);
            assert!(!(*result));
        } else {
            panic!("wrong_response")
        }

        // subscribe
        let request = Request::subscribe_sh(script).id(1);
        client.send(&request);
        index.insert(request.id, request);
        let response = &client.recv(&index).unwrap()[0];
        if let Response::SHSubscribe(SHSubscribeResponse { id, result }) = response {
            assert_eq!(*id, 1);
            assert_eq!(*result, None);
        } else {
            panic!("wrong_response")
        }

        // unsubscribe w/ subscription we expect result==true
        let request = Request::unsubscribe_sh(script).id(2);
        client.send(&request);
        index.insert(request.id, request);
        let response = &client.recv(&index).unwrap()[0];
        if let Response::SHUnsubscribe(SHUnsubscribeResponse { id, result }) = response {
            assert_eq!(*id, 2);
            assert!((*result));
        } else {
            panic!("wrong_response")
        }
    }

    #[test]
    fn sh_get_balance() {
        let mut client = acinq_client();
        client.connect();

        let raw_script = Vec::from_hex("0014992f8cc4f6d284acac5f603e233592b566c04b2a").unwrap();
        let script = Script::from_bytes(raw_script.as_slice());

        let mut index = HashMap::new();
        let request = Request::sh_get_balance(script);
        client.send(&request);
        index.insert(request.id, request);
        let response = &client.recv(&index).unwrap()[0];
        if let Response::SHGetBalance(_) = response {
        } else {
            panic!("wrong response")
        }
    }

    #[test]
    fn sh_get_history() {
        let mut client = acinq_client();
        client.connect();

        let raw_script = Vec::from_hex("0014992f8cc4f6d284acac5f603e233592b566c04b2a").unwrap();
        let script = Script::from_bytes(raw_script.as_slice());

        let mut index = HashMap::new();
        let request = Request::sh_get_history(script);
        client.send(&request);
        index.insert(request.id, request);
        let response = &client.recv(&index).unwrap()[0];
        if let Response::SHGetHistory(_) = response {
        } else {
            panic!("wrong response")
        }
    }

    // NOTE: not supported by electrs
    // #[test]
    // fn sh_get_mempool() {
    //     let mut client = tcp_client();
    //     client.connect();
    //
    //     let script = Script::from_bytes(&[0x00]);
    //
    //     let mut index = HashMap::new();
    //     let request = Request::sh_get_mempool(script);
    //     client.send(&request);
    //     index.insert(request.id, request);
    //     println!("get_mempool: {}", client.recv_str().unwrap());
    //     // let response = client.recv(&index).unwrap()[0];
    // }

    #[test]
    fn sh_list_unspent() {
        let mut client = acinq_client();
        client.connect();

        let raw_script = Vec::from_hex("0014992f8cc4f6d284acac5f603e233592b566c04b2a").unwrap();
        let script = Script::from_bytes(raw_script.as_slice());

        let mut index = HashMap::new();
        let request = Request::sh_list_unspent(script);
        client.send(&request);
        index.insert(request.id, request);
        let response = &client.recv(&index).unwrap()[0];
        if let Response::SHListUnspent(_) = response {
        } else {
            panic!("wrong response")
        }
    }

    #[test]
    fn features() {
        let mut client = acinq_client();
        client.connect();

        let mut index = HashMap::new();
        let request = Request::features();
        client.send(&request);
        index.insert(request.id, request);
        let response = &client.recv(&index).unwrap()[0];
        if let Response::Features(_) = response {
            //
        } else {
            panic!("wrong response")
        }
    }

    #[test]
    fn donation() {
        let mut client = acinq_client();
        client.connect();

        let mut index = HashMap::new();
        let request = Request::donation();
        client.send(&request);
        index.insert(request.id, request);
        let response = &client.recv(&index).unwrap()[0];
        if let Response::Donation(_) = response {
            //
        } else {
            panic!("wrong response")
        }
    }

    #[test]
    fn estimate_fee() {
        let mut client = acinq_client();
        client.connect();

        let mut index = HashMap::new();
        let request = Request::estimate_fee(10);
        client.send(&request);
        index.insert(request.id, request);
        let response = &client.recv(&index).unwrap()[0];
        if let Response::EstimateFee(_) = response {
            //
        } else {
            panic!("wrong response")
        }
    }

    #[test]
    fn fee_histogram() {
        let mut client = acinq_client();
        client.connect();

        let mut index = HashMap::new();
        let request = Request::get_fee_histogram();
        client.send(&request);
        index.insert(request.id, request);
        let response = &client.recv(&index).unwrap()[0];
        if let Response::FeeHistogram(_) = response {
            //
        } else {
            panic!("wrong response")
        }
    }

    #[test]
    fn relay_fee() {
        let mut client = acinq_client();
        client.connect();

        let mut index = HashMap::new();
        let request = Request::relay_fee();
        client.send(&request);
        index.insert(request.id, request);
        // println!("{}", client.recv_str().unwrap());
        let response = &client.recv(&index).unwrap()[0];
        if let Response::RelayFee(_) = response {
            //
        } else {
            panic!("wrong response")
        }
    }

    #[test]
    fn tx_get_merkle() {
        let mut client = acinq_client();
        client.connect();

        let raw_outpoint = "e03a9a4b5c557f6ee3400a29ff1475d1df73e9cddb48c2391abdc391d8c1504a:0";
        let outpoint = OutPoint::from_str(raw_outpoint).unwrap();

        let mut index = HashMap::new();
        let request = Request::tx_get_merkle(outpoint.txid, 200_000);
        client.send(&request);
        index.insert(request.id, request);
        // println!("{}", client.recv_str().unwrap());
        let response = &client.recv(&index).unwrap()[0];
        if let Response::TxGetMerkle(_) = response {
            //
        } else {
            panic!("wrong response")
        }
    }

    #[test]
    fn tx_from_position() {
        let mut client = acinq_client();
        client.connect();

        let mut index = HashMap::new();
        let request = Request::tx_from_pos(200_000, 3, false);
        client.send(&request);
        index.insert(request.id, request);
        let response = &client.recv(&index).unwrap()[0];
        if let Response::TxFromposition(_) = response {
            //
        } else {
            panic!("wrong response")
        }

        let request = Request::tx_from_pos(300_000, 125, true).id(1);
        client.send(&request);
        index.insert(request.id, request);
        let response = &client.recv(&index).unwrap()[0];
        if let Response::TxFromposition(_) = response {
            //
        } else {
            panic!("wrong response")
        }
    }
}
