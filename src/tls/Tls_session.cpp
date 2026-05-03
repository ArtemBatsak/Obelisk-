#include "tls/Tls_session.h"
#include <fstream>
#include <filesystem>

// Generate a self-signed certificate and private key in PEM format using OpenSSL
std::pair<std::string, std::string> generate_self_signed_cert_pem()
{
    EVP_PKEY* pkey = nullptr;
    X509* x509 = nullptr;
    BIGNUM* bn = nullptr;

    std::string priv_pem, cert_pem;

    do {
        bn = BN_new();
        if (!bn) break;
        if (!BN_set_word(bn, RSA_F4)) break;

        RSA* rsa = RSA_new();
        if (!rsa) break;
        if (!RSA_generate_key_ex(rsa, 2048, bn, nullptr)) { RSA_free(rsa); break; }

        pkey = EVP_PKEY_new();
        if (!pkey) { RSA_free(rsa); break; }
        if (!EVP_PKEY_assign_RSA(pkey, rsa)) { RSA_free(rsa); EVP_PKEY_free(pkey); pkey = nullptr; break; }

        x509 = X509_new();
        if (!x509) break;

        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
        X509_set_pubkey(x509, pkey);

        X509_NAME* name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"RU", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"GrayCompany", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"grayserver.local", -1, -1, 0);

        X509_set_issuer_name(x509, name);

        if (!X509_sign(x509, pkey, EVP_sha256())) break;

        BIO* bio_priv = BIO_new(BIO_s_mem());
        BIO* bio_cert = BIO_new(BIO_s_mem());
        if (!bio_priv || !bio_cert) { BIO_free(bio_priv); BIO_free(bio_cert); break; }

        if (!PEM_write_bio_PrivateKey(bio_priv, pkey, nullptr, nullptr, 0, nullptr, nullptr)) { BIO_free(bio_priv); BIO_free(bio_cert); break; }
        if (!PEM_write_bio_X509(bio_cert, x509)) { BIO_free(bio_priv); BIO_free(bio_cert); break; }

        // extract as std::string
        char* data_ptr = nullptr;
        long len = BIO_get_mem_data(bio_priv, &data_ptr);
        if (len > 0) priv_pem.assign(data_ptr, static_cast<size_t>(len));

        len = BIO_get_mem_data(bio_cert, &data_ptr);
        if (len > 0) cert_pem.assign(data_ptr, static_cast<size_t>(len));

        BIO_free(bio_priv);
        BIO_free(bio_cert);

    } while (false);

    if (x509) X509_free(x509);
    if (pkey) EVP_PKEY_free(pkey);
    if (bn) BN_free(bn);

    return { priv_pem, cert_pem };
}

// Load PEM-encoded certificate and private key into an OpenSSL context
bool load_cert_and_key_into_context(asio::ssl::context& ctx,
    const std::string& cert_pem,
    const std::string& key_pem)
{
    SSL_CTX* ssl_ctx = ctx.native_handle();
    if (!ssl_ctx) return false;

    BIO* bio_cert = BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
    BIO* bio_key = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));

    if (!bio_cert || !bio_key) return false;

    X509* x509 = PEM_read_bio_X509(bio_cert, nullptr, nullptr, nullptr);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio_key, nullptr, nullptr, nullptr);

    BIO_free(bio_cert);
    BIO_free(bio_key);

    if (!x509 || !pkey) {
        if (x509) X509_free(x509);
        if (pkey) EVP_PKEY_free(pkey);
        return false;
    }

    bool ok = SSL_CTX_use_certificate(ssl_ctx, x509) == 1 &&
        SSL_CTX_use_PrivateKey(ssl_ctx, pkey) == 1 &&
        SSL_CTX_check_private_key(ssl_ctx) == 1;

    X509_free(x509);
    EVP_PKEY_free(pkey);

    return ok;
}

bool generate_self_signed_cert_files(const std::string& cert_path, const std::string& key_path)
{
    auto pem = generate_self_signed_cert_pem();
    const std::string& key_pem = pem.first;
    const std::string& cert_pem = pem.second;

    if (key_pem.empty() || cert_pem.empty()) {
        return false;
    }

    try {
        std::ofstream cert_file(cert_path, std::ios::binary | std::ios::trunc);
        cert_file << cert_pem;
        cert_file.close();
        if (!cert_file.good()) {
            return false;
        }

        std::ofstream key_file(key_path, std::ios::binary | std::ios::trunc);
        key_file << key_pem;
        key_file.close();
        if (!key_file.good()) {
            return false;
        }

#ifndef _WIN32
        std::filesystem::permissions(
            key_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace
        );
#endif
    }
    catch (...) {
        return false;
    }

    return true;
}
