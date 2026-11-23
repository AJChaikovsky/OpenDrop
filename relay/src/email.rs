//! Emailing sign-in links through Resend (https://resend.com).
//!
//! Set `RESEND_API_KEY` (a Fly secret on the hosted relay) and links go by
//! email; without it the relay prints them to its log (`LogMailer`). Until
//! the relay has its own domain, Resend's shared sender only delivers to the
//! address the Resend account was made with, which suits a personal relay.

use crate::Mailer;

/// Resend's shared sender, usable without a domain of your own.
pub const DEFAULT_FROM: &str = "OpenDrop <onboarding@resend.dev>";
pub const RESEND_API: &str = "https://api.resend.com/emails";

pub struct ResendMailer {
    api_key: String,
    from: String,
    endpoint: String,
    http: reqwest::Client,
}

/// rustls needs one process-wide crypto backend; OpenDrop uses ring.
/// Installing it again is harmless.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

impl ResendMailer {
    pub fn new(api_key: impl Into<String>, from: impl Into<String>) -> Self {
        Self::with_endpoint(api_key, from, RESEND_API)
    }

    /// Send to another endpoint (tests use a local fake).
    pub fn with_endpoint(
        api_key: impl Into<String>,
        from: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Self {
        install_crypto_provider();
        Self {
            api_key: api_key.into(),
            from: from.into(),
            endpoint: endpoint.into(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .expect("an HTTP client"),
        }
    }

    /// The email for `link`, as Resend's JSON.
    pub fn message(&self, email: &str, link: &str) -> serde_json::Value {
        serde_json::json!({
            "from": self.from,
            "to": [email],
            "subject": "Your OpenDrop sign-in link",
            "text": format!(
                "Open this link to sign in to OpenDrop. It works once, for 15 minutes:\n\n{link}\n\n\
                 If you didn't ask for this, ignore this email; nothing happens without the link."
            ),
            "html": format!(
                "<p>Open this link to sign in to OpenDrop. It works once, for 15 minutes:</p>\
                 <p><a href=\"{link}\">Sign in to OpenDrop</a></p>\
                 <p style=\"color:#666\">If you didn't ask for this, ignore this email; nothing \
                 happens without the link.</p>"
            ),
        })
    }
}

impl Mailer for ResendMailer {
    fn send_login_link(&self, email: &str, link: &str) {
        let request = self
            .http
            .post(&self.endpoint)
            .bearer_auth(&self.api_key)
            .json(&self.message(email, link));
        let (email, link) = (email.to_owned(), link.to_owned());
        tokio::spawn(async move {
            match request.send().await {
                Ok(response) if response.status().is_success() => {
                    println!("sign-in link emailed to {email}");
                }
                outcome => {
                    let why = match outcome {
                        Ok(response) => {
                            let status = response.status();
                            let body = response.text().await.unwrap_or_default();
                            format!("{status} {}", body.chars().take(300).collect::<String>())
                        }
                        Err(e) => e.to_string(),
                    };
                    // Don't strand the person: the link still reaches the log.
                    eprintln!("emailing {email} failed ({why}); sign-in link for {email}: {link}");
                }
            }
        });
    }
}
