// tests/test_pki_lifecycle.c

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#include "core_crypto/crypto_client.h"
#include "pki/pki_handler.h"

// --- 测试辅助宏 ---
#define TEST_ASSERT(condition, message) do { \
    if (!(condition)) { \
        fprintf(stderr, "TEST FAILED: %s (%s:%d)\n", message, __FILE__, __LINE__); \
        return -1; \
    } \
} while(0)

// --- 测试辅助函数 (从 main.c 复制而来，用于创建测试证书) ---

static int add_ext(X509 *cert, int nid, char *value) {
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex) return 0;
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
}

int generate_test_ca(char** ca_key_pem, char** ca_cert_pem) {
    // [Implementation copied from main.c]
    int ret = -1;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    BIO *key_bio = NULL, *cert_bio = NULL;
    
    unsigned char ca_sk_seed[crypto_sign_SEEDBYTES];
    memset(ca_sk_seed, 0xCA, sizeof(ca_sk_seed));

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, ca_sk_seed, sizeof(ca_sk_seed));
    if (!pkey) goto cleanup;

    cert = X509_new();
    if (!cert) goto cleanup;

    X509_set_version(cert, 2L);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 31536000L);
    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"Test System Root CA", -1, -1, 0);
    X509_set_issuer_name(cert, name);

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
    memcpy(*ca_key_pem, key_mem->data, key_mem->length);
    (*ca_key_pem)[key_mem->length] = '\0';

    BIO_get_mem_ptr(cert_bio, &cert_mem);
    *ca_cert_pem = (char*)malloc(cert_mem->length + 1);
    memcpy(*ca_cert_pem, cert_mem->data, cert_mem->length);
    (*ca_cert_pem)[cert_mem->length] = '\0';
    
    ret = 0;

cleanup:
    EVP_PKEY_free(pkey); X509_free(cert); BIO_free(key_bio); BIO_free(cert_bio);
    return ret;
}

int sign_csr_with_ca(char** user_cert_pem, const char* csr_pem, const char* ca_key_pem, const char* ca_cert_pem) {
    // [Implementation copied from main.c, with OCSP URI addition]
    int ret = -1;
    BIO *csr_bio = NULL, *ca_key_bio = NULL, *ca_cert_bio = NULL, *out_bio = NULL;
    X509_REQ *req = NULL;
    EVP_PKEY *ca_key = NULL;
    X509 *ca_cert = NULL, *user_cert = NULL;

    csr_bio = BIO_new_mem_buf(csr_pem, -1);
    ca_key_bio = BIO_new_mem_buf(ca_key_pem, -1);
    ca_cert_bio = BIO_new_mem_buf(ca_cert_pem, -1);
    if(!csr_bio || !ca_key_bio || !ca_cert_bio) goto cleanup;

    req = PEM_read_bio_X509_REQ(csr_bio, NULL, NULL, NULL);
    ca_key = PEM_read_bio_PrivateKey(ca_key_bio, NULL, NULL, NULL);
    ca_cert = PEM_read_bio_X509(ca_cert_bio, NULL, NULL, NULL);
    if(!req || !ca_key || !ca_cert) goto cleanup;

    user_cert = X509_new();
    if(!user_cert) goto cleanup;

    X509_set_version(user_cert, 2L);
    ASN1_INTEGER_set(X509_get_serialNumber(user_cert), randombytes_random()); // Use a random serial
    X509_set_issuer_name(user_cert, X509_get_subject_name(ca_cert));
    X509_gmtime_adj(X509_getm_notBefore(user_cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(user_cert), 31536000L); // 1 year validity
    
    EVP_PKEY* req_pubkey = X509_REQ_get_pubkey(req);
    X509_set_subject_name(user_cert, X509_REQ_get_subject_name(req));
    X509_set_pubkey(user_cert, req_pubkey);
    EVP_PKEY_free(req_pubkey);
    
    // Add OCSP URI for testing revocation
    add_ext(user_cert, NID_info_access, "OCSP;URI:http://127.0.0.1:8888");

    if (X509_sign(user_cert, ca_key, NULL) <= 0) goto cleanup;

    out_bio = BIO_new(BIO_s_mem());
    if(!out_bio) goto cleanup;

    if(!PEM_write_bio_X509(out_bio, user_cert)) goto cleanup;
    
    BUF_MEM *out_mem;
    BIO_get_mem_ptr(out_bio, &out_mem);
    *user_cert_pem = (char*)malloc(out_mem->length + 1);
    memcpy(*user_cert_pem, out_mem->data, out_mem->length);
    (*user_cert_pem)[out_mem->length] = '\0';

    ret = 0;

cleanup:
    BIO_free(csr_bio); BIO_free(ca_key_bio); BIO_free(ca_cert_bio); BIO_free(out_bio);
    X509_REQ_free(req); EVP_PKEY_free(ca_key); X509_free(ca_cert); X509_free(user_cert);
    return ret;
}

// --- 测试用例 ---

/**
 * @brief 测试 CSR 的生成和基本内容验证
 */
int test_csr_generation() {
    printf("  Running test: test_csr_generation...\n");
    master_key_pair mkp;
    mkp.sk = NULL;
    char* csr_pem = NULL;
    const char* username = "testuser@domain.tld";

    TEST_ASSERT(generate_master_key_pair(&mkp) == 0, "Key pair generation failed");
    
    int res = generate_csr(&mkp, username, &csr_pem);
    TEST_ASSERT(res == 0, "generate_csr should succeed");
    TEST_ASSERT(csr_pem != NULL, "CSR PEM string should not be NULL");
    
    // 基本的 PEM 格式和内容检查
    TEST_ASSERT(strstr(csr_pem, "-----BEGIN CERTIFICATE REQUEST-----") != NULL, "CSR should have a valid PEM header");
    TEST_ASSERT(strstr(csr_pem, username) != NULL, "CSR should contain the username");

    free_csr_pem(csr_pem);
    free_master_key_pair(&mkp);
    printf("    ... PASSED\n");
    return 0;
}

/**
 * @brief 测试从证书中提取出的公钥是否与原始公钥一致
 */
int test_public_key_extraction_consistency() {
    printf("  Running test: test_public_key_extraction_consistency...\n");
    master_key_pair user_mkp;
    user_mkp.sk = NULL;
    char* csr_pem = NULL;
    char* ca_key_pem = NULL;
    char* ca_cert_pem = NULL;
    char* user_cert_pem = NULL;
    unsigned char extracted_pk[MASTER_PUBLIC_KEY_BYTES];

    // 1. 创建所有必需的密钥和证书
    TEST_ASSERT(generate_master_key_pair(&user_mkp) == 0, "User keygen failed");
    TEST_ASSERT(generate_test_ca(&ca_key_pem, &ca_cert_pem) == 0, "Test CA generation failed");
    TEST_ASSERT(generate_csr(&user_mkp, "consistency.check", &csr_pem) == 0, "CSR generation failed");
    TEST_ASSERT(sign_csr_with_ca(&user_cert_pem, csr_pem, ca_key_pem, ca_cert_pem) == 0, "CSR signing failed");
    
    // 2. 从生成的证书中提取公钥
    int res = extract_public_key_from_cert(user_cert_pem, extracted_pk);
    TEST_ASSERT(res == 0, "extract_public_key_from_cert should succeed");

    // 3. 验证提取的公钥与原始公钥完全匹配
    TEST_ASSERT(sodium_memcmp(user_mkp.pk, extracted_pk, MASTER_PUBLIC_KEY_BYTES) == 0, 
                "Extracted public key must match the original public key");

    // Cleanup
    free_master_key_pair(&user_mkp);
    free_csr_pem(csr_pem);
    free(ca_key_pem);
    free(ca_cert_pem);
    free(user_cert_pem);

    printf("    ... PASSED\n");
    return 0;
}


int main() {
    // 两个库都需要初始化
    if (crypto_client_init() != 0 || pki_init() != 0) {
        fprintf(stderr, "Fatal: Library initialization failed\n");
        return 1;
    }

    printf("--- Running PKI Lifecycle Test Suite ---\n");
    if (test_csr_generation() != 0) return 1;
    if (test_public_key_extraction_consistency() != 0) return 1;
    
    printf("--- PKI Lifecycle Test Suite: ALL PASSED ---\n\n");
    return 0;
}