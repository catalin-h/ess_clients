use crate::{ConnectionDetails, User, UserUpdate};
use anyhow::{Context, Result};
use hyper::{
    body::to_bytes,
    client::{Client, HttpConnector},
    Body, Method, Request, StatusCode, Uri,
};
use hyper_rustls::HttpsConnector;
use rustls::{Certificate, PrivateKey, RootCertStore};
use serde_json::Value as JsonValue;
use std::fs::File;
use std::io::BufReader;

fn default_url(admin: bool) -> String {
    match std::env::var("ESS_WS_URL") {
        Ok(url) => url,
        _ => format!("https://ess.local:{}", if admin { 8081 } else { 8080 }),
    }
}

fn default_root_ca_file(admin: bool) -> String {
    match std::env::var(if admin {
        "ESS_ADMIN_ROOT_CA"
    } else {
        "ESS_PAM_ROOT_CA"
    }) {
        Ok(url) => url,
        _ => format!(
            "./certs/{0}/{0}-root-ca.crt",
            if admin { "admin" } else { "pam" }
        ),
    }
}

fn default_admin_cert_file(admin: bool) -> String {
    match std::env::var(if admin {
        "ESS_ADMIN_CERT"
    } else {
        "ESS_PAM_CERT"
    }) {
        Ok(url) => url,
        _ => format!(
            "./certs/{0}/{0}-client-crt.pem",
            if admin { "admin" } else { "pam" }
        ),
    }
}

fn default_admin_cert_key_file(admin: bool) -> String {
    match std::env::var(if admin {
        "ESS_ADMIN_CERT_KEY"
    } else {
        "ESS_PAM_CERT_KEY"
    }) {
        Ok(url) => url,
        _ => format!(
            "./certs/{0}/{0}-client-key.pem",
            if admin { "admin" } else { "pam" }
        ),
    }
}

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

    pub fn build(self) -> Result<EssHttpsClient> {
        let is_admin = !self.conn_details.pam;
        let url = self.conn_details.url.unwrap_or(default_url(is_admin));
        let url: Uri = url.as_str().parse().context(url)?;

        log::debug!("Using url: {}", url);

        let root_ca = get_root_store(
            &self
                .conn_details
                .cafile
                .unwrap_or(default_root_ca_file(is_admin)),
        )?;
        let cert = load_certs(
            &self
                .conn_details
                .cert
                .unwrap_or(default_admin_cert_file(is_admin)),
        )?;
        let key = load_private_key(
            &self
                .conn_details
                .key
                .unwrap_or(default_admin_cert_key_file(is_admin)),
        )?;

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

fn handle_http_status(status: StatusCode, username: &str) -> Result<()> {
    log::debug!("HTTP status: {}", &status);
    match status {
        StatusCode::BAD_REQUEST => anyhow::bail!("Invalid parameters for request"),
        StatusCode::FORBIDDEN => anyhow::bail!("Forbidden, invalid one time password"),
        StatusCode::NOT_FOUND => anyhow::bail!("Username '{}', not found", username),
        StatusCode::CONFLICT => anyhow::bail!("Username '{}', is already registered", username),
        e if e.is_client_error() => anyhow::bail!("Client error: {}", e),
        e if e.is_server_error() => anyhow::bail!("Server error: {}", e),
        _ => Ok(()),
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

        log::debug!(
            "Begin GET username {} details request: {} ...",
            username,
            url
        );

        let response = self.client.request(request).await?;

        handle_http_status(response.status(), username)?;

        let body = response.into_body();
        let body = to_bytes(body)
            .await
            .map_err(|e| anyhow::anyhow!("Could not get body: {:?}", e))?;

        serde_json::from_slice(&body).map_or_else(|_| Ok(JsonValue::default()), |j| Ok(j))
    }

    pub async fn add_user(&self, user: User, qr_code: bool) -> Result<String> {
        let url = self.make_url("/api/admin/employee")?;
        let body = serde_json::to_value(&user)?;

        let request = Request::builder()
            .method(Method::POST)
            .header("EssSendQRCodeLink", if qr_code { "yes" } else { "no" })
            .uri(&url)
            .body(Body::from(body.to_string()))?;

        log::debug!("Begin POST add user request: {} ...", url);

        let response = self.client.request(request).await?;

        handle_http_status(response.status(), &user.username)?;

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

        log::debug!(
            "Begin PUT update username {} request: {} ...",
            username,
            url
        );

        let response = self.client.request(request).await?;

        handle_http_status(response.status(), username)
    }

    pub async fn delete_user(&self, username: &str) -> Result<()> {
        let path = format!("/api/admin/employee/{}", username);
        let url = self.make_url(&path)?;

        let request = Request::builder()
            .method(Method::DELETE)
            .uri(&url)
            .body(Body::empty())?;

        log::debug!("Begin DELETE username {} request: {} ...", username, url);

        let response = self.client.request(request).await?;

        handle_http_status(response.status(), username)
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

        log::debug!(
            "Begin POST verify username {} OTP request: {} ...",
            username,
            url
        );

        let response = self.client.request(request).await?;

        handle_http_status(response.status(), username)
    }
}
