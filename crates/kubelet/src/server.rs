/// Server is an HTTP(S) server for answering Kubelet callbacks.
///
/// Logs and exec calls are the main things that a server should handle.
use async_stream::stream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{
    server::{conn::Http, Builder},
    Body, Error, Method, Request, Response, StatusCode,
};
use log::{debug, error, info};
use native_tls::{Identity, TlsAcceptor};
use tokio::net::TcpListener;
use tokio::stream::StreamExt;
use tokio::sync::Mutex;

use std::net::SocketAddr;
use std::sync::Arc;

use crate::kubelet::Provider;

/// Start the Krustlet HTTP(S) server
///
/// This is a primitive implementation of an HTTP provider for the internal API.
/// TODO: Support TLS/SSL.
pub async fn start_webserver<T: 'static + Provider + Send + Sync>(
    provider: Arc<Mutex<T>>,
    address: &SocketAddr,
) -> Result<(), failure::Error> {
    let identity = tokio::fs::read("identity.pfx")
        .await
        .expect("Could not read identity file");
    let identity =
        Identity::from_pkcs12(&identity, "password").expect("Could not parse indentiy file");

    let acceptor = tokio_tls::TlsAcceptor::from(TlsAcceptor::new(identity).unwrap());
    let acceptor = Arc::new(acceptor);
    let service = make_service_fn(move |_| {
        let provider = provider.clone();
        async {
            Ok::<_, Error>(service_fn(move |req: Request<Body>| {
                let provider = provider.clone();

                async move {
                    let path: Vec<&str> = req.uri().path().split('/').collect();
                    let path_len = path.len();
                    let response = if path_len < 2 {
                        get_ping()
                    } else {
                        match (req.method(), path[1], path_len) {
                            (&Method::GET, "containerLogs", 5) => {
                                get_container_logs(&*provider.lock().await, &req).await
                            }
                            (&Method::POST, "exec", 5) => post_exec(&*provider.lock().await, &req),
                            _ => {
                                let mut response = Response::new(Body::from("Not Found"));
                                *response.status_mut() = StatusCode::NOT_FOUND;
                                response
                            }
                        }
                    };
                    Ok::<_, Error>(response)
                }
            }))
        }
    });

    let mut listener = TcpListener::bind(address).await.unwrap();
    let mut incoming = listener.incoming();
    let accept = hyper::server::accept::from_stream(stream! {
        loop {
            match incoming.next().await {
                Some(Ok(stream)) => match acceptor.clone().accept(stream).await {
                    result @ Ok(_) => yield result,
                    Err(e) => break,
                },
                _ => break,
            }
        }
    });
    let server = Builder::new(accept, Http::new()).serve(service);

    info!("starting webserver at: {:?}", address);

    server.await?;

    Ok(())
}

/// Return a simple status message
fn get_ping() -> Response<Body> {
    Response::new(Body::from("this is the Krustlet HTTP server"))
}

/// Get the logs from the running WASM module
///
/// Implements the kubelet path /containerLogs/{namespace}/{pod}/{container}
async fn get_container_logs<T: Provider + Sync>(
    provider: &T,
    req: &Request<Body>,
) -> Response<Body> {
    // Basic validation steps
    let path: Vec<&str> = req.uri().path().split('/').collect();
    // Because of the leading slash, index 0 is an empty string. Index 1 is the
    // container logs path
    let (namespace, pod, container) = match path.as_slice() {
        [_, _, namespace, pod, container] => (*namespace, *pod, *container),
        _ => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from(format!(
                    "Resource {} not found",
                    req.uri().path()
                )))
                .unwrap()
        }
    };
    if namespace.is_empty() || pod.is_empty() || container.is_empty() {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from(format!(
                "Resource {} not found",
                req.uri().path()
            )))
            .unwrap();
    }

    // END validation

    debug!(
        "Got container log request for container {} in pod {} in namespace {}",
        container, pod, namespace
    );

    match provider
        .logs(namespace.into(), pod.into(), container.into())
        .await
    {
        Ok(data) => Response::new(Body::from(data)),
        // TODO: This should detect not implemented vs. regular error (pod not found, etc.)
        Err(e) => {
            error!("Error fetching logs: {}", e);
            let mut res = Response::new(Body::from("Not Implemented"));
            *res.status_mut() = StatusCode::NOT_IMPLEMENTED;
            res
        }
    }
}
/// Run a pod exec command and get the output
///
/// Implements the kubelet path /exec/{namespace}/{pod}/{container}
fn post_exec<T: Provider>(_provider: &T, _req: &Request<Body>) -> Response<Body> {
    let mut res = Response::new(Body::from("Not Implemented"));
    *res.status_mut() = StatusCode::NOT_IMPLEMENTED;
    res
}
