use std::fmt;
use std::io;

use log::error;
use serde::Serialize;
use warp::http;
use warp::hyper;
use warp::{Rejection, Reply};

use crate::ssrf;

#[derive(Serialize)]
struct ErrorMessage {
    code: u16,
    message: String,
}

pub(crate) async fn recover(err: Rejection) -> Result<impl Reply, Rejection> {
    if let Some(ref err) = err.find::<Error>() {
        let error = ErrorMessage {
            code: err.status_code(),
            message: err.to_string(),
        };

        error!("Recovering from error `{}`", error.message);

        return Ok(warp::reply::with_status(
            warp::reply::json(&error),
            warp::http::StatusCode::from_u16(error.code).unwrap(),
        ));
    }

    Err(err)
}

#[derive(Debug)]
pub(crate) enum Error {
    /// The caller asked for a target that is not allowed to be fetched.
    BlockedTarget(String),
    Http(http::Error),
    Hyper(hyper::Error),
    InvalidHeaderValue(hyper::header::InvalidHeaderValue),
    Io(io::Error),
    Reqwest(reqwest::Error),
    UrlParse(url::ParseError),
}

/// Turns a failure from the HTTP client into ours.
///
/// A refusal raised inside the client — by the resolver, when the lookup it
/// makes for the connection names this device — comes back wrapped in a
/// `reqwest::Error`. Taken at face value that is an `Error::Reqwest`, which
/// answers 500 and drops the reason, so the path that exists precisely to catch
/// a rebinding host would report itself as our own fault. Look through the
/// wrapping and put the refusal back.
pub(crate) fn from_client_error(err: reqwest::Error) -> Error {
    refusal_in_chain(&err).unwrap_or(Error::Reqwest(err))
}

fn refusal_in_chain(err: &(dyn std::error::Error + 'static)) -> Option<Error> {
    let mut current = Some(err);

    while let Some(err) = current {
        if let Some(Error::BlockedTarget(reason)) = err.downcast_ref::<Error>() {
            return Some(Error::BlockedTarget(reason.clone()));
        }

        if err.is::<ssrf::DeviceAddress>() {
            return Some(Error::BlockedTarget(err.to_string()));
        }

        current = err.source();
    }

    None
}

impl Error {
    /// A refused target is the caller's fault; everything else is ours.
    fn status_code(&self) -> u16 {
        match self {
            Error::BlockedTarget(_) => 403,
            _ => 500,
        }
    }
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::BlockedTarget(reason) => write!(f, "{reason}"),
            Error::Http(err) => err.fmt(f),
            Error::Hyper(err) => err.fmt(f),
            Error::InvalidHeaderValue(err) => err.fmt(f),
            Error::Io(err) => err.fmt(f),
            Error::Reqwest(err) => err.fmt(f),
            Error::UrlParse(err) => err.fmt(f),
        }
    }
}

impl From<http::Error> for Error {
    fn from(err: http::Error) -> Error {
        Error::Http(err)
    }
}

impl From<hyper::Error> for Error {
    fn from(err: hyper::Error) -> Error {
        Error::Hyper(err)
    }
}

impl From<hyper::header::InvalidHeaderValue> for Error {
    fn from(err: hyper::header::InvalidHeaderValue) -> Error {
        Error::InvalidHeaderValue(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        Error::Reqwest(err)
    }
}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Error {
        Error::UrlParse(err)
    }
}

impl warp::reject::Reject for Error {}

// impl From<Error> for warp::reject::Rejection {
//     fn from(error: Error) -> warp::reject::Rejection {
//         warp::reject::custom(error)
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    /// Stands in for the layers reqwest puts between its own error and whatever
    /// a policy or a resolver handed it.
    #[derive(Debug)]
    struct Wrapper(Box<dyn std::error::Error + Send + Sync>);

    impl fmt::Display for Wrapper {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "wrapped: {}", self.0)
        }
    }

    impl std::error::Error for Wrapper {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self.0.as_ref())
        }
    }

    fn wrap(err: impl std::error::Error + Send + Sync + 'static) -> Wrapper {
        Wrapper(Box::new(Wrapper(Box::new(err))))
    }

    #[test]
    fn refusal_in_chain_when_a_blocked_target_is_buried_should_find_it() {
        let err = wrap(Error::BlockedTarget(String::from(
            "Target is an address of this device: http://127.0.0.1:4040/",
        )));

        let refusal = refusal_in_chain(&err).expect("the refusal should survive the wrapping");

        assert_eq!(refusal.status_code(), 403);
        assert_eq!(
            refusal.to_string(),
            "Target is an address of this device: http://127.0.0.1:4040/"
        );
    }

    #[test]
    fn refusal_in_chain_when_the_resolver_refused_should_be_a_blocked_target() {
        let err = wrap(ssrf::DeviceAddress);

        let refusal = refusal_in_chain(&err).expect("the refusal should survive the wrapping");

        assert_eq!(refusal.status_code(), 403);
        assert_eq!(refusal.to_string(), "Target is an address of this device");
    }

    #[test]
    fn refusal_in_chain_when_nothing_refused_should_be_none() {
        let err = wrap(io::Error::new(io::ErrorKind::ConnectionRefused, "nope"));

        assert!(refusal_in_chain(&err).is_none());
    }
}
