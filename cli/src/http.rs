//! The one HTTP client: reqwest on rustls with the ring provider (the only
//! crypto library in the build). Connections are pooled across all callers.

use std::sync::OnceLock;

fn install_ring() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        // Fails only if a provider is already installed, which is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Shared client; follows redirects (reqwest drops Authorization when a
/// redirect changes host, as GHCR's blob redirects to separate storage do).
pub fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        install_ring();
        reqwest::Client::builder().user_agent("hartland").build().expect("HTTP client")
    })
}

/// A client that reports redirects instead of following them.
pub fn no_redirect_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        install_ring();
        reqwest::Client::builder()
            .user_agent("hartland")
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("HTTP client")
    })
}
