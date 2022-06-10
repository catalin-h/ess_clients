use crate::{ConnectionDetails, User, UserUpdate};
use anyhow::{Context, Result};
use hyper::{
    body::to_bytes,
    client::{Client, HttpConnector},
    Body, Method, Request, Uri,
};
use hyper_rustls::HttpsConnector;
use rustls::{Certificate, PrivateKey, RootCertStore};
use serde_json::Value as JsonValue;
use std::fs::File;
use std::io::BufReader;

pub struct EssHttpsClient {
    url: Uri,
    client: Client<HttpsConnector<HttpConnector>, Body>,
}

pub struct EssBuilder {
    conn_details: ConnectionDetails,
}

fn load_certs(filename: &str) -> Result<Vec<Certificate>> {
    log::debug!("loading cert file: {} ..", filename);

    let certfile = File::open(filename).context(filename.to_string())?;
    let mut reader = BufReader::new(certfile);
    Ok(rustls_pemfile::certs(&mut reader)
        .context(filename.to_string())?
        .iter()
        .map(|v| Certificate(v.clone()))
        .collect())
}

fn load_private_key(filename: &str) -> Result<PrivateKey> {
    log::debug!("loading private key file: {} ..", filename);

    let keyfile = File::open(filename).context(filename.to_string())?;
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).context(filename.to_string())? {
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(PrivateKey(key)),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(PrivateKey(key)),
            Some(rustls_pemfile::Item::ECKey(key)) => return Ok(PrivateKey(key)),
            None => break,
            _ => {}
        }
    }

    anyhow::bail!("Unsupported private key format for file: {}", filename);
}

fn get_root_store(file: &str) -> Result<RootCertStore> {
    log::debug!("loading root ca file: {} ..", file);
    let mut roots = RootCertStore::empty();

    for root in load_certs(file)? {
        roots.add(&root)?;
    }

    Ok(roots)
}

impl EssBuilder {
    pub fn new(conn_details: ConnectionDetails) -> Self {
        EssBuilder {
            conn_details: conn_details,
        }
    }

    pub fn build(&self) -> Result<EssHttpsClient> {
        let url: Uri = self
            .conn_details
            .url
            .as_str()
            .parse()
            .context(self.conn_details.url.clone())?;

        log::debug!("Using url: {}", url);

        let root_ca = get_root_store(&self.conn_details.cafile)?;
        let cert = load_certs(&self.conn_details.cert)?;
        let key = load_private_key(&self.conn_details.key)?;

        // Rustls client config
        let tls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_ca)
            .with_single_cert(cert, key)?;

        // Prepare the HTTPS connector using the tls config
        let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_only()
            .enable_http1()
            .build();

        let https_client: Client<_, Body> = Client::builder().build(https_connector);

        Ok(EssHttpsClient {
            url: url,
            client: https_client,
        })
    }
}

impl EssHttpsClient {
    fn make_url(&self, path: &str) -> Result<Uri> {
        let authority = self
            .url
            .authority()
            .ok_or(anyhow::anyhow!("No authority in URL: {}", &self.url))?;
        let url = Uri::builder()
            .scheme("https")
            .authority(authority.clone())
            .path_and_query(path)
            .build()?;
        Ok(url)
    }

    pub async fn get_user(&self, username: &str) -> Result<JsonValue> {
        let path = format!("/api/admin/employee/{}", username);
        let url = self.make_url(&path)?;
        let request = Request::builder()
            .method(Method::GET)
            .uri(&url)
            .body(Body::empty())?;

        log::debug!("Begin GET request: {} ...", url);

        let response = self.client.request(request).await?;

        log::debug!("HTTP status: {}", response.status());

        let body = response.into_body();
        let body = to_bytes(body)
            .await
            .map_err(|e| anyhow::anyhow!("Could not get body: {:?}", e))?;

        serde_json::from_slice(&body).map_or_else(|_| Ok(JsonValue::default()), |j| Ok(j))
    }

    pub async fn add_user(&self, user: User, qr_code: bool) -> Result<String> {
        let url = self.make_url("/api/admin/employee")?;
        let body = serde_json::to_value(user)?;

        let request = Request::builder()
            .method(Method::POST)
            .header("EssSendQRCodeLink", if qr_code { "yes" } else { "no" })
            .uri(&url)
            .body(Body::from(body.to_string()))?;

        log::debug!("Begin POST request: {} ...", url);

        let response = self.client.request(request).await?;

        log::debug!("HTTP status: {}", response.status());

        let body = response.into_body();
        let body = to_bytes(body)
            .await
            .map_err(|e| anyhow::anyhow!("Could not get body: {:?}", e))?;

        Ok(String::from_utf8_lossy(&body).to_string())
    }

    pub async fn update_user(&self, username: &str, data: UserUpdate) -> Result<()> {
        let path = format!("/api/admin/employee/{}", username);
        let url = self.make_url(&path)?;
        let body = serde_json::to_value(data)?;

        let request = Request::builder()
            .method(Method::PUT)
            .uri(&url)
            .body(Body::from(body.to_string()))?;

        log::debug!("Begin PUT request: {} ...", url);

        let response = self.client.request(request).await?;

        log::debug!("HTTP status: {}", response.status());

        Ok(())
    }

    pub async fn delete_user(&self, username: &str) -> Result<()> {
        let path = format!("/api/admin/employee/{}", username);
        let url = self.make_url(&path)?;

        let request = Request::builder()
            .method(Method::DELETE)
            .uri(&url)
            .body(Body::empty())?;

        log::debug!("Begin DELETE request: {} ...", url);

        let response = self.client.request(request).await?;

        log::debug!("HTTP status: {}", response.status());

        Ok(())
    }

    pub async fn verify_user(&self, username: &str, code: &str) -> Result<()> {
        let path = format!("/api/admin/employee/{}", username);
        let url = self.make_url(&path)?;
        let body = serde_json::json!({
            "username": username,
            "oneTimePassword": code,
        });

        let request = Request::builder()
            .method(Method::POST)
            .uri(&url)
            .body(Body::from(body.to_string()))?;

        log::debug!("Begin POST verify request: {} ...", url);

        let response = self.client.request(request).await?;

        log::debug!("HTTP status: {}", response.status());

        Ok(())
    }
}
