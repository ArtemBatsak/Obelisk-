#include "tls/Tls_session.h"
#include <cstdio>
#include <fstream>
#include <filesystem>
#include <vector>

namespace {

EVP_PKEY* generate_ec_pkey()
{
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx) return nullptr;
    if (EVP_PKEY_keygen_init(pctx) <= 0
        || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0
        || EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = nullptr;
    }
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

bool set_random_serial(X509* x509)
{
    BIGNUM* serial_bn = BN_new();
    if (!serial_bn) return false;
    if (!BN_rand(serial_bn, 64, 0, 0)) { BN_free(serial_bn); return false; }
    ASN1_INTEGER* serial_asn1 = BN_to_ASN1_INTEGER(serial_bn, nullptr);
    BN_free(serial_bn);
    if (!serial_asn1) return false;
    const bool ok = X509_set_serialNumber(x509, serial_asn1) == 1;
    ASN1_INTEGER_free(serial_asn1);
    return ok;
}

} // namespace

// Generate a self-signed EC P-256 certificate and private key in PEM format.
// EC is used instead of RSA 2048 because key generation is orders of magnitude
// faster, while the PEM wire format seen by Phantom remains unchanged.
std::pair<std::string, std::string> generate_self_signed_cert_pem()
{
    EVP_PKEY* pkey = nullptr;
    X509* x509 = nullptr;

    std::string priv_pem, cert_pem;

    do {
        pkey = generate_ec_pkey();
        if (!pkey) break;

        x509 = X509_new();
        if (!x509) break;

        if (!set_random_serial(x509)) break;

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

    return { priv_pem, cert_pem };
}

std::string certificate_fingerprint(const std::string& cert_pem)
{
    if (cert_pem.empty()) return {};

    BIO* bio = BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
    if (!bio) return {};
    X509* x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!x509) return {};

    int len = i2d_X509(x509, nullptr);
    if (len <= 0) { X509_free(x509); return {}; }

    std::vector<unsigned char> der(static_cast<size_t>(len));
    unsigned char* p = der.data();
    if (i2d_X509(x509, &p) != len) { X509_free(x509); return {}; }
    X509_free(x509);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(der.data(), der.size(), hash);

    std::string fp;
    fp.reserve(SHA256_DIGEST_LENGTH * 3 - 1);
    char buf[4];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        std::snprintf(buf, sizeof(buf), "%02X", hash[i]);
        if (i > 0) fp.push_back(':');
        fp.append(buf);
    }
    return fp;
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

    if (!bio_cert || !bio_key) {
        if (bio_cert) BIO_free(bio_cert);
        if (bio_key) BIO_free(bio_key);
        return false;
    }

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
