use std::{collections::HashMap, path::{Path, PathBuf}, rc::Rc, sync::Arc};

use reqwest::{cookie::Jar, header::{HeaderMap, HeaderValue}, multipart::{Form, Part}, Client, Url};
use serde::Deserialize;
use anyhow::{Context, Result};

use crate::config::{CertificatePair, CertificateRef, CredentialPathBuf};

//use crate::config::CertificateConfig;

#[derive(Clone, Deserialize, Debug)]
pub struct RawConfig {
    pub certificate: CertificateRef,

    pub url: Url,

    pub password_file: Option<CredentialPathBuf>
}

#[derive(Clone, Debug)]
pub struct Config<CertT> {
    pub certificate: CertT,

    pub url: Url
}

impl <'de> Deserialize<'de> for Config<CertificateRef> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>
    {
        let raw = RawConfig::deserialize(deserializer)?;

        todo!()
    }
}




#[derive(Deserialize)]
struct NewSessionResponse {
    user_id: u32,

    #[serde(rename = "CSRFToken")]
    csrf_token: String
}

#[derive(Deserialize, Debug)]
struct CertificateInfoResponse {
    id: u32,
    certificate_available: u32,
    certificate_date: String,
    private_key_date: String
}

// pub async fn file<T: AsRef<Path>>(path: T) -> io::Result<Part> {
//     let path = path.as_ref();
//     let file_name = path.file_name()
//         .map(|filename| filename.to_string_lossy().into_owned());
//     let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
//     let mime = mime_guess::from_ext(ext).first_or_octet_stream();
//     let file = File::open(path).await?;
//     let field = Part::stream(file).mime(mime);

//     Ok(if let Some(file_name) = file_name {
//         field.file_name(file_name)
//     } else {
//         field
//     })
// }

//fn login() -> 

/// Update MegaRac BMC TLS certificates
/// 
/// Note that the HTTPS connections are made to ignore invalid certificates
/// (`danger_accept_invalid_certs(true)`) to work around:
/// 1. previously generated self-signed certificates being installed but not trusted by this tool
///     (e.g., not in system trust store)
/// 2. a bug in the BMC firmware where it strips a fullchain.pem and only stores the first certificate in the chain,
///     which causes even valid certificates to be seen as invalid by native-tls and other tools. For example,
///     on my test X570D4U board with a Lets Encrypt cert, openssl s_client -connect returns
///         verify error:num=20:unable to get local issuer certificate
///         verify error:num=21:unable to verify the first certificate
pub async fn update_certificate(config: &Config<Rc<CertificatePair>>) -> Result<()> {
    todo!();

    /*let base_url = config.url.join("/api/").expect("valid base_url");
    let cookie_jar = Arc::new(Jar::default());

    let api_url = |path: &str| -> Url {
        base_url.join(path).expect("valid API url")
    };

    let build_client = |csrf_token: Option<String>| -> Result<Client> {
        let mut builder = Client::builder()
            .cookie_provider(cookie_jar.clone())
            .danger_accept_invalid_certs(true); // see comment above

        if let Some(csrf_token) = csrf_token {
            let mut headers = HeaderMap::new();
            headers.append("X-CSRFTOKEN", csrf_token.parse().unwrap());

            builder = builder.default_headers(headers);
        }

        builder.build().context("failed to build a Client")
    };

    // STAGE 1: login to create a session cookie and get CSRF token
    let client = build_client(None)?;

    let login_response = {
        let mut creds = HashMap::new();
        creds.insert("username", config.url.username());
        creds.insert("password", config.url.password()
                                    .or(config.password.as_deref())
                                    .unwrap_or_default()
                                );

        let response: NewSessionResponse = client.post(api_url("session"))
            .form(&creds)
            .send().await.context("failed to send request")?
            .error_for_status()?
            .json().await.context("failed to decode JSON response")?;

        response
    };

    let client = build_client(Some(login_response.csrf_token))?;

    let certificate_form = Form::new();
        //.part("new_certificate", Part::file(config.certificate.as_ref().expect("certificate"))?)
        //.part("new_private_key", Part::file(config.private_key.as_ref().expect("private key"))?);

    let response = client.post(api_url("settings/ssl/certificate"))
        .multipart(certificate_form)
        .send().await.context("failed to send request")?
        .error_for_status()?
        .text().await.context("failed to decode JSON response");

    // let response: CertificateInfoResponse = client.get(api_url("settings/ssl/certificate-info"))
    //     .send().expect("send request")
    //     .json().expect("valid JSON response");




    // let response = client.delete(api_url("settings/ssl/certificate")).send()
    //     .expect("send request")
    //     .text().expect("response");


    println!("{response:?}");

    Ok(())*/
}