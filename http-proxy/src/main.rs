use hyper::upgrade::Upgraded;
use hyper::{
    service::service_fn, Body, Client, Method, Request, Response, Server, StatusCode, Uri,
};
use hyper_tls::HttpsConnector;
use std::net::SocketAddr;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tower::make::Shared;
use tracing::{info, instrument};
use tracing_subscriber;

#[instrument(skip(req))]
async fn proxy(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    info!("Received request: Method = {:?}, Uri = {:?}", method, uri);

    // CONNECT for HTTPS
    if method == Method::CONNECT {
        if let Some(addr) = host_addr(&uri) {
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, addr).await {
                            eprintln!("Server I/O error: {}", e);
                        };
                    }
                    Err(e) => eprintln!("Upgrade error: {}", e),
                }
            });
            return Ok(Response::new(Body::empty()));
        } else {
            eprintln!("CONNECT host is not a valid socket address: {:?}", uri);
            let mut response =
                Response::new(Body::from("CONNECT must be to a valid socket address"));
            *response.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(response);
        }
    }

    // Forward HTTP requests
    let new_uri: Uri = format!("http://httpbin.org{}", uri.path()).parse().unwrap();
    let body_bytes = hyper::body::to_bytes(req.into_body()).await?;
    info!("Request body: {:?}", String::from_utf8_lossy(&body_bytes));

    let mut req_builder = Request::builder().method(method).uri(new_uri);

    for (key, value) in headers.iter() {
        req_builder = req_builder.header(key, value);
    }

    // req_builder = req_builder
    //     .header("Host", "github.com")
    //     .header("User-Agent", "Mozilla/5.0 (compatible; hyper/0.14)")
    //     .header("Accept", "*/*");

    let req = req_builder.body(Body::from(body_bytes)).unwrap();

    let mut res = forward_request(req).await?;
    log_and_rebuild_response(&mut res).await
}

async fn forward_request(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    client.request(req).await
}

async fn log_and_rebuild_response(
    res: &mut Response<Body>,
) -> Result<Response<Body>, hyper::Error> {
    let status = res.status();
    let headers = res.headers().clone();

    let body_bytes = hyper::body::to_bytes(res.body_mut()).await?;
    info!("Response body: {:?}", String::from_utf8_lossy(&body_bytes));

    let mut res_builder = Response::builder().status(status);

    for (key, value) in headers.iter() {
        res_builder = res_builder.header(key, value);
    }

    Ok(res_builder.body(Body::from(body_bytes)).unwrap())
}

fn host_addr(uri: &Uri) -> Option<String> {
    uri.authority().map(|auth| auth.to_string())
}

async fn tunnel(mut upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    let mut server = TcpStream::connect(addr).await?;
    let (from_client, from_server) = copy_bidirectional(&mut upgraded, &mut server).await?;
    println!(
        "Client wrote {} bytes, server wrote {} bytes",
        from_client, from_server
    );
    Ok(())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let make_service = Shared::new(service_fn(proxy));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let server = Server::bind(&addr).serve(make_service);

    if let Err(e) = server.await {
        eprintln!("Server error: {}", e);
    }
}
