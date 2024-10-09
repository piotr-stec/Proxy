use hyper::{service::service_fn, Body, Client, Request, Response, Server};
use std::net::SocketAddr;
use tower::make::Shared;
use tracing::{info, instrument};
use tracing_subscriber;

#[instrument(skip(req))]
async fn log(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    let body_bytes = hyper::body::to_bytes(req.into_body()).await?;
    info!("Request body: {:?}", String::from_utf8_lossy(&body_bytes));

    let mut req_builder = Request::builder().method(method).uri(uri);

    for (key, value) in headers.iter() {
        req_builder = req_builder.header(key, value);
    }

    let req = req_builder.body(Body::from(body_bytes)).unwrap();

    let mut res = handle(req).await?;

    log_and_rebuild_response(&mut res).await
}

async fn handle(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let client = Client::new();
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let make_service = Shared::new(service_fn(log));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let server = Server::bind(&addr).serve(make_service);

    if let Err(e) = server.await {
        println!("error: {}", e);
    }
}
