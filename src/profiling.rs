#[cfg(not(windows))]
mod imp {
    use http_body_util::Full;
    use hyper::body::{Bytes, Incoming};
    use hyper::header::{CONTENT_TYPE, LOCATION};
    use hyper::service::service_fn;
    use hyper::{Method, Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use log::{error, info};
    use pprof::ProfilerGuard;
    use protobuf::Message;
    #[cfg(test)]
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    #[cfg(test)]
    static PROFILE_STUB: AtomicBool = AtomicBool::new(false);

    pub struct ProfileServer {
        shutdown: oneshot::Sender<()>,
        handle: tokio::task::JoinHandle<()>,
    }

    pub async fn start(port: &str) -> Result<ProfileServer, String> {
        let listen_addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&listen_addr)
            .await
            .map_err(|e| e.to_string())?;
        info!("Profile server listening on {}", listen_addr);
        let (shutdown, mut rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => {
                        break;
                    }
                    accept_result = listener.accept() => {
                        let (stream, _) = match accept_result {
                            Ok(value) => value,
                            Err(err) => {
                                error!("Profile server accept error: {}", err);
                                continue;
                            }
                        };
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let service = service_fn(handle_request);
                            if let Err(err) = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, service)
                                .await
                            {
                                error!("Profile server connection error: {}", err);
                            }
                        });
                    }
                }
            }
        });
        Ok(ProfileServer { shutdown, handle })
    }

    impl ProfileServer {
        pub async fn stop(self) {
            let _ = self.shutdown.send(());
            let _ = self.handle.await;
        }
    }

    async fn handle_request(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
        if req.method() != Method::GET {
            return Ok(simple_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            ));
        }

        let path = req.uri().path();
        match path {
            "/" => Ok(redirect_response("/debug/pprof")),
            "/debug/pprof" => Ok(redirect_response("/debug/pprof/")),
            "/debug/pprof/" => Ok(simple_response(StatusCode::OK, pprof_index_body())),
            "/debug/pprof/profile" => handle_profile(req.uri().query()).await,
            _ => Ok(simple_response(StatusCode::NOT_FOUND, "not found")),
        }
    }

    fn redirect_response(location: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(LOCATION, location)
            .body(Full::new(Bytes::from_static(b"")))
            .unwrap_or_else(|_| simple_response(StatusCode::INTERNAL_SERVER_ERROR, ""))
    }

    fn simple_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b""))))
    }

    fn pprof_index_body() -> &'static str {
        "pprof endpoints:\n\n/debug/pprof/profile?seconds=N\n"
    }

    async fn handle_profile(query: Option<&str>) -> Result<Response<Full<Bytes>>, hyper::Error> {
        if use_profile_stub() {
            return Ok(simple_response(StatusCode::OK, "profile stub"));
        }
        let seconds = parse_profile_seconds(query).unwrap_or(30);
        let guard = match ProfilerGuard::new(100) {
            Ok(g) => g,
            Err(err) => {
                error!("Failed to start profiler: {}", err);
                return Ok(simple_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to start profiler",
                ));
            }
        };
        tokio::time::sleep(Duration::from_secs(seconds)).await;

        let report = match guard.report().build() {
            Ok(r) => r,
            Err(err) => {
                error!("Failed to build profile: {}", err);
                return Ok(simple_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to build profile",
                ));
            }
        };

        let profile = match report.pprof() {
            Ok(p) => p,
            Err(err) => {
                error!("Failed to encode profile: {}", err);
                return Ok(simple_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to encode profile",
                ));
            }
        };

        let mut body = Vec::new();
        if let Err(err) = profile.write_to_vec(&mut body) {
            error!("Failed to serialize profile: {}", err);
            return Ok(simple_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to serialize profile",
            ));
        }

        let resp = Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| simple_response(StatusCode::INTERNAL_SERVER_ERROR, ""));
        Ok(resp)
    }

    fn parse_profile_seconds(query: Option<&str>) -> Option<u64> {
        let query = query?;
        for pair in query.split('&') {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next().unwrap_or("");
            if key == "seconds"
                && let Ok(secs) = value.parse::<u64>()
            {
                return Some(secs);
            }
        }
        None
    }

    fn use_profile_stub() -> bool {
        #[cfg(test)]
        if PROFILE_STUB.load(Ordering::Relaxed) {
            return true;
        }
        std::env::var("DNSSEEDER_PROFILE_STUB")
            .map(|value| value == "1")
            .unwrap_or(false)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tokio::net::TcpStream;

        async fn get_body(addr: &str, path: &str) -> Vec<u8> {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let request = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                path, addr
            );
            tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes())
                .await
                .unwrap();
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf)
                .await
                .unwrap();
            buf
        }

        fn status_line(response: &[u8]) -> Option<&str> {
            let text = std::str::from_utf8(response).ok()?;
            text.lines().next()
        }

        #[tokio::test]
        async fn test_profile_endpoints() {
            PROFILE_STUB.store(true, Ordering::Relaxed);
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (shutdown, mut rx) = oneshot::channel();
            let handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut rx => break,
                        accept_result = listener.accept() => {
                            let (stream, _) = accept_result.unwrap();
                            tokio::spawn(async move {
                                let io = TokioIo::new(stream);
                                let service = service_fn(handle_request);
                                let _ = hyper::server::conn::http1::Builder::new()
                                    .serve_connection(io, service)
                                    .await;
                            });
                        }
                    }
                }
            });

            let base = addr.to_string();
            let body = get_body(&base, "/debug/pprof/").await;
            let status = status_line(&body).unwrap_or("");
            assert!(status.contains("200"));

            let profile_body = get_body(&base, "/debug/pprof/profile?seconds=1").await;
            let status = status_line(&profile_body).unwrap_or("");
            assert!(status.contains("200"));

            let _ = shutdown.send(());
            let _ = handle.await;
            PROFILE_STUB.store(false, Ordering::Relaxed);
        }
    }
}

#[cfg(windows)]
mod imp {
    pub struct ProfileServer;

    pub async fn start(_port: &str) -> Result<ProfileServer, String> {
        Err("pprof profiling is not supported on Windows".to_string())
    }

    impl ProfileServer {
        pub async fn stop(self) {}
    }
}

pub use imp::start;
pub type ProfileServer = imp::ProfileServer;
