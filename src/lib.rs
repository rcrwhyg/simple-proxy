use async_trait::async_trait;
use pingora::{http::ResponseHeader, prelude::*};
use tracing::info;

pub struct SimpleProxy {}

#[async_trait]
impl ProxyHttp for SimpleProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = HttpPeer::new("127.0.0.1:3000".to_string(), false, "localhost".to_string());
        info!("upstream_peer: {:?}", peer);
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        info!("upstream_request_filter: {:?}", upstream_request);
        upstream_request.insert_header("user-agent", "SimpleProxy/0.1")?;
        Ok(())
    }

    fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        info!("upstream_response_filter: {:?}", upstream_response);
        upstream_response.insert_header("x-simple-proxy", "v0.1")?;
        if let Some(server) = upstream_response.remove_header("server") {
            info!("server: {:?}", server);
            upstream_response.insert_header("server", server)?;
        } else {
            upstream_response.insert_header("server", "SimpleProxy/0.1")?;
        }
        Ok(())
    }
}
