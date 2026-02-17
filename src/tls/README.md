TLS Utils (Asio + OpenSSL)

In-memory generation of a self-signed TLS certificate and loading it directly into asio::ssl::context.

RSA 2048

X.509, PEM

No .crt / .key files

Dependencies

Asio (standalone)

OpenSSL (-lssl -lcrypto)

Example
asio::ssl::context ctx(asio::ssl::context::tls_server);
auto [key, cert] = generate_self_signed_cert_pem();
load_cert_and_key_into_context(ctx, cert, key);


Self-signed certificate. For dev / test use only.