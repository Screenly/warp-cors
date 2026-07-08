use log::trace;
use reqwest::Client;
use warp::http::request::Parts;
use warp::hyper::{self, Body, Response};

use crate::error;

pub type Request = hyper::Request<Body>;

#[derive(Clone)]
pub(crate) struct HttpsClient {
    client: Client,
}

impl HttpsClient {
    pub(crate) fn new() -> Self {
        let client = Client::new();
        HttpsClient { client }
    }

    pub(crate) async fn request(&self, request: Request) -> Result<Response<Body>, error::Error> {
        let (parts, body) = request.into_parts();

        let Parts {
            method,
            uri,
            headers,
            ..
        } = parts;

        let url = reqwest::Url::parse(&uri.to_string())?;
        let body = reqwest::Body::wrap_stream(body);
        let request = self
            .client
            .request(to_reqwest_method(&method), url)
            .headers(to_reqwest_headers(&headers))
            .body(body)
            .build()?;

        trace!("Sending request");
        let response = self.client.execute(request).await?;
        trace!("Got response");

        let response_headers = response
            .headers()
            .iter()
            .filter(|(k, _)| k != &reqwest::header::SET_COOKIE);

        let mut builder = Response::builder();

        for (key, value) in response_headers {
            builder = builder.header(key.as_str(), value.as_bytes());
        }

        let response = builder
            .status(response.status().as_u16())
            .body(Body::wrap_stream(response.bytes_stream()))?;

        Ok(response)
    }
}

/// Convert a `warp`/`http` 0.2 method into the `http` 1.0 method used by `reqwest`.
fn to_reqwest_method(method: &warp::http::Method) -> reqwest::Method {
    reqwest::Method::from_bytes(method.as_str().as_bytes())
        .expect("a valid method is always a valid method")
}

/// Convert a `warp`/`http` 0.2 header map into the `http` 1.0 map used by `reqwest`.
fn to_reqwest_headers(headers: &warp::http::HeaderMap) -> reqwest::header::HeaderMap {
    let mut out = reqwest::header::HeaderMap::with_capacity(headers.len());
    for (key, value) in headers {
        if let (Ok(key), Ok(value)) = (
            reqwest::header::HeaderName::from_bytes(key.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            out.append(key, value);
        }
    }
    out
}
