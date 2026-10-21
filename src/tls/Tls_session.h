#pragma once

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <string>
#include <utility>
// OpenSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/bio.h>

// Generate self-signed certificate and private key in PEM format
std::pair<std::string, std::string> generate_self_signed_cert_pem();
bool load_cert_and_key_into_context(asio::ssl::context& ctx, const std::string& cert_pem, const std::string& key_pem);
bool generate_self_signed_cert_files(const std::string& cert_path, const std::string& key_path);
