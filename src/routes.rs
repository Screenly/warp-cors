use warp::http::header::ORIGIN;
use warp::{Filter, Rejection, Reply};

use crate::client::HttpsClient;
use crate::error;
use crate::filters;
use crate::handlers;

pub fn routes(host: String) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    let client = HttpsClient::new();
    preflight()
        .or(proxy(host, client))
        // Recover before the CORS headers, so a refusal carries them too. A 403
        // without allow-origin is one the browser will not let the page read, so
        // the reason the refusal was given for reaches the journal and nobody
        // else - least of all the developer whose app was refused.
        .recover(error::recover)
        .and(
            warp::header::optional(ORIGIN.as_str())
                .map(|v: Option<String>| v.unwrap_or_else(|| String::from("*"))),
        )
        .map(filters::allow_origin)
        .map(filters::allow_credentials)
        // Log last, so the line records the response as it was sent. Earlier and
        // it sees a refusal as an unhandled rejection and calls it a 500.
        .with(warp::log("warp_cors"))
}

fn preflight() -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Copy {
    filters::is_url_path()
        .and(warp::options())
        .and(warp::header("access-control-request-method"))
        .and(warp::header("access-control-request-headers"))
        .and_then(handlers::preflight_request)
}

fn proxy(
    host: String,
    client: HttpsClient,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    filters::proxied_request(host)
        .and(filters::with_client(client))
        .and_then(handlers::proxy_request)
        .map(filters::expose_all_headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_routes() {
        let host = "example.org".to_owned();
        let routes = routes(host);

        let request = warp::test::request();
        assert!(!request.matches(&routes).await);

        let request = warp::test::request()
            .method("OPTIONS")
            .header("access-control-request-method", "GET")
            .header("access-control-request-headers", "Origin")
            .header("origin", "localhost")
            .path("http://localhost/http://example.org");
        assert!(request.matches(&routes).await);

        let request = warp::test::request()
            .method("OPTIONS")
            .header("access-control-request-method", "GET")
            .path("http://localhost/http://example.org");
        assert!(request.matches(&routes).await);

        let request = warp::test::request()
            .method("GET")
            .header("origin", "localhost")
            .path("http://localhost/http://example.org");
        assert!(request.matches(&routes).await);

        let request = warp::test::request()
            .method("GET")
            .path("http://localhost/http://example.org");
        assert!(request.matches(&routes).await);
    }

    #[tokio::test]
    async fn proxy_when_target_is_loopback_should_refuse() {
        let routes = routes("warp-cors".to_owned());

        let response = warp::test::request()
            .method("GET")
            .header("origin", "http://127.0.0.1:34567")
            .path("/http://127.0.0.1:4040/api/v3/screens/")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), 403);
    }

    // A refusal the page cannot read is a refusal whose reason only ever reaches
    // the journal, so the header matters as much as the status.
    #[tokio::test]
    async fn proxy_when_target_is_loopback_the_page_should_be_able_to_read_the_refusal() {
        let routes = routes("warp-cors".to_owned());

        let response = warp::test::request()
            .method("GET")
            .header("origin", "http://127.0.0.1:34567")
            .path("/http://127.0.0.1:4040/api/v3/screens/")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), 403);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .expect("a refusal the page cannot read is no use to anyone"),
            "http://127.0.0.1:34567"
        );
    }

    #[tokio::test]
    async fn proxy_when_target_is_ipv6_loopback_should_refuse() {
        let routes = routes("warp-cors".to_owned());

        let response = warp::test::request()
            .method("GET")
            .header("origin", "http://127.0.0.1:34567")
            .path("/http://[::1]:3030/")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), 403);
    }

    #[tokio::test]
    async fn test_preflight() {
        let preflight = preflight();

        let request = warp::test::request();
        assert!(!request.matches(&preflight).await);

        let request = warp::test::request()
            .method("OPTIONS")
            .path("http://localhost/http://example.org");
        assert!(!request.matches(&preflight).await);

        let request = warp::test::request()
            .method("OPTIONS")
            .header("access-control-request-method", "GET")
            .path("http://localhost/http://example.org");
        assert!(!request.matches(&preflight).await);

        let request = warp::test::request()
            .method("OPTIONS")
            .header("access-control-request-method", "GET")
            .header("origin", "localhost")
            .path("http://localhost/http://example.org");
        assert!(!request.matches(&preflight).await);

        let request = warp::test::request()
            .method("GET")
            .header("access-control-request-method", "GET")
            .header("access-control-request-headers", "Origin")
            .header("origin", "localhost")
            .path("http://localhost/http://example.org");
        assert!(!request.matches(&preflight).await);

        let request = warp::test::request()
            .method("OPTIONS")
            .header("access-control-request-method", "GET")
            .header("access-control-request-headers", "Origin")
            .path("http://localhost/http://example.org");
        assert!(request.matches(&preflight).await);

        let request = warp::test::request()
            .method("OPTIONS")
            .header("access-control-request-method", "GET")
            .header("access-control-request-headers", "Origin")
            .header("origin", "localhost")
            .path("http://localhost/http://example.org");
        assert!(request.matches(&preflight).await);
    }
}
