#include "test_helpers.h"
#include "core_crypto/crypto_client.h" // For MASTER_PUBLIC_KEY_BYTES

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sodium/randombytes.h>

#include <string.h>
#include <stdlib.h>

// 内部静态辅助函数，用于向证书添加 X.509 v3 扩展
static int add_ext(X509 *cert, int nid, char *value) {
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    // 将颁发者和主体都设置为证书本身（用于自签名或设置 SKI）
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex) {
        return 0;
    }
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
}

int generate_test_ca(char** ca_key_pem, char** ca_cert_pem, unsigned char seed_byte) {
    int ret = -1;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    BIO *key_bio = NULL, *cert_bio = NULL;
    
    // 使用确定的种子生成可重复的 CA 密钥
    unsigned char ca_sk_seed[crypto_sign_SEEDBYTES];
    memset(ca_sk_seed, seed_byte, sizeof(ca_sk_seed));

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, ca_sk_seed, sizeof(ca_sk_seed));
    if (!pkey) goto cleanup;

    cert = X509_new();
    if (!cert) goto cleanup;

    X509_set_version(cert, 2L); // 必须是 v3 证书
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 31536000L); // 默认一年有效期
    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"Test System Root CA", -1, -1, 0);
    X509_set_issuer_name(cert, name);

    // 添加使其成为合格 CA 的 v3 扩展
    add_ext(cert, NID_basic_constraints, "critical,CA:TRUE");
    add_ext(cert, NID_key_usage, "critical,digitalSignature,keyCertSign,cRLSign");
    add_ext(cert, NID_subject_key_identifier, "hash");

    if (!X509_sign(cert, pkey, NULL)) goto cleanup;

    key_bio = BIO_new(BIO_s_mem());
    cert_bio = BIO_new(BIO_s_mem());
    if(!key_bio || !cert_bio) goto cleanup;

    if(!PEM_write_bio_PrivateKey(key_bio, pkey, NULL, NULL, 0, NULL, NULL)) goto cleanup;
    if(!PEM_write_bio_X509(cert_bio, cert)) goto cleanup;
    
    BUF_MEM *key_mem, *cert_mem;
    BIO_get_mem_ptr(key_bio, &key_mem);
    *ca_key_pem = (char*)malloc(key_mem->length + 1);
    if (!*ca_key_pem) goto cleanup;
    memcpy(*ca_key_pem, key_mem->data, key_mem->length);
    (*ca_key_pem)[key_mem->length] = '\0';

    BIO_get_mem_ptr(cert_bio, &cert_mem);
    *ca_cert_pem = (char*)malloc(cert_mem->length + 1);
    if (!*ca_cert_pem) { free(*ca_key_pem); *ca_key_pem = NULL; goto cleanup; }
    memcpy(*ca_cert_pem, cert_mem->data, cert_mem->length);
    (*ca_cert_pem)[cert_mem->length] = '\0';
    
    ret = 0;

cleanup:
    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free(key_bio);
    BIO_free(cert_bio);
    return ret;
}

int sign_csr_with_ca(char** user_cert_pem, const char* csr_pem,
                     const char* ca_key_pem, const char* ca_cert_pem,
                     long not_before_offset_sec, long not_after_offset_sec) {
    int ret = -1;
    BIO *csr_bio = NULL, *ca_key_bio = NULL, *ca_cert_bio = NULL, *out_bio = NULL;
    X509_REQ *req = NULL;
    EVP_PKEY *ca_key = NULL;
    X509 *ca_cert = NULL, *user_cert = NULL;
    EVP_PKEY* req_pubkey = NULL;

    csr_bio = BIO_new_mem_buf(csr_pem, -1);
    ca_key_bio = BIO_new_mem_buf(ca_key_pem, -1);
    ca_cert_bio = BIO_new_mem_buf(ca_cert_pem, -1);
    user_cert = X509_new();
    if(!csr_bio || !ca_key_bio || !ca_cert_bio || !user_cert) goto cleanup;

    req = PEM_read_bio_X509_REQ(csr_bio, NULL, NULL, NULL);
    ca_key = PEM_read_bio_PrivateKey(ca_key_bio, NULL, NULL, NULL);
    ca_cert = PEM_read_bio_X509(ca_cert_bio, NULL, NULL, NULL);
    if(!req || !ca_key || !ca_cert) goto cleanup;

    X509_set_version(user_cert, 2L);
    // 使用随机序列号，更符合实际
    ASN1_INTEGER_set(X509_get_serialNumber(user_cert), (long)randombytes_random());
    
    // 设置证书有效期
    X509_gmtime_adj(X509_getm_notBefore(user_cert), not_before_offset_sec);
    X509_gmtime_adj(X509_getm_notAfter(user_cert), not_after_offset_sec);
    
    X509_set_issuer_name(user_cert, X509_get_subject_name(ca_cert));
    
    // 从 CSR 中提取公钥和主题
    req_pubkey = X509_REQ_get_pubkey(req);
    X509_set_subject_name(user_cert, X509_REQ_get_subject_name(req));
    X509_set_pubkey(user_cert, req_pubkey);
    
    // 添加 AIA 扩展，指向一个假的 OCSP 服务器，用于测试 OCSP 逻辑
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, NULL, NID_info_access, "OCSP;URI:http://127.0.0.1:8888");
    if (ex) {
        X509_add_ext(user_cert, ex, -1);
        X509_EXTENSION_free(ex);
    }
    
    if (X509_sign(user_cert, ca_key, NULL) <= 0) goto cleanup;

    out_bio = BIO_new(BIO_s_mem());
    if(!out_bio || !PEM_write_bio_X509(out_bio, user_cert)) goto cleanup;
    
    BUF_MEM *out_mem;
    BIO_get_mem_ptr(out_bio, &out_mem);
    *user_cert_pem = (char*)malloc(out_mem->length + 1);
    if (*user_cert_pem) {
        memcpy(*user_cert_pem, out_mem->data, out_mem->length);
        (*user_cert_pem)[out_mem->length] = '\0';
        ret = 0;
    }

cleanup:
    EVP_PKEY_free(req_pubkey);
    BIO_free(csr_bio);
    BIO_free(ca_key_bio);
    BIO_free(ca_cert_bio);
    BIO_free(out_bio);
    X509_REQ_free(req);
    EVP_PKEY_free(ca_key);
    X509_free(ca_cert);
    X509_free(user_cert);
    return ret;
}