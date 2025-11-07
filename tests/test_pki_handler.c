#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h> // 包含 ERR_print_errors_fp

// 包含我们需要测试的模块的头文件
#include "pki/pki_handler.h"
#include "core_crypto/crypto_client.h"

// --- 测试框架宏 ---
int tests_run = 0;
int tests_failed = 0;

#define FAIL() printf("\033[31m[FAIL]\033[0m %s:%d\n", __FILE__, __LINE__)
#define _assert(test) do { if (!(test)) { FAIL(); tests_failed++; return; } } while(0)
#define _verify(test) do { _assert(test); } while(0)
#define RUN_TEST(test) do { printf("  Running test: %s...", #test); tests_failed = 0; test(); tests_run++; if(tests_failed == 0) printf("\033[32m [PASS]\033[0m\n"); } while(0)

// --- 测试辅助函数声明 ---
int generate_test_ca(char** ca_key_pem, char** ca_cert_pem);
int sign_csr_with_ca(char** user_cert_pem, const char* csr_pem, const char* ca_key_pem, const char* ca_cert_pem);

// --- 测试用例 ---

void test_csr_generation() {
    master_key_pair mkp;
    _verify(generate_master_key_pair(&mkp) == 0);

    const char* username = "test@user.com";
    char* csr_pem = NULL;

    _verify(generate_csr(&mkp, username, &csr_pem) == 0);
    _verify(csr_pem != NULL);
    _verify(strlen(csr_pem) > 0);

    _verify(strstr(csr_pem, "-----BEGIN CERTIFICATE REQUEST-----") != NULL);
    _verify(strstr(csr_pem, "-----END CERTIFICATE REQUEST-----") != NULL);

    free_csr_pem(csr_pem);
    free_master_key_pair(&mkp);
}

void test_certificate_validation_successful() {
    master_key_pair mkp;
    _verify(generate_master_key_pair(&mkp) == 0);
    char* csr_pem = NULL;
    _verify(generate_csr(&mkp, "gooduser@example.com", &csr_pem) == 0);

    char* ca_key = NULL, *ca_cert = NULL, *user_cert = NULL;
    _verify(generate_test_ca(&ca_key, &ca_cert) == 0);
    _verify(sign_csr_with_ca(&user_cert, csr_pem, ca_key, ca_cert) == 0);
    _verify(user_cert != NULL);

    _verify(verify_user_certificate(user_cert, ca_cert, "gooduser@example.com") == 0);

    free(ca_key);
    free(ca_cert);
    free(user_cert);
    free_csr_pem(csr_pem);
    free_master_key_pair(&mkp);
}

void test_certificate_validation_failures() {
    master_key_pair mkp;
    _verify(generate_master_key_pair(&mkp) == 0);
    char* csr_pem = NULL;
    _verify(generate_csr(&mkp, "user@example.com", &csr_pem) == 0);

    char* ca_key = NULL, *ca_cert = NULL, *user_cert = NULL;
    _verify(generate_test_ca(&ca_key, &ca_cert) == 0);
    _verify(sign_csr_with_ca(&user_cert, csr_pem, ca_key, ca_cert) == 0);
    
    _verify(verify_user_certificate(user_cert, ca_cert, "wronguser@example.com") == -3);

    char* untrusted_ca_key = NULL, *untrusted_ca_cert = NULL;
    _verify(generate_test_ca(&untrusted_ca_key, &untrusted_ca_cert) == 0);
    _verify(verify_user_certificate(user_cert, untrusted_ca_cert, "user@example.com") == -2);

    free(ca_key);
    free(ca_cert);
    free(user_cert);
    free_csr_pem(csr_pem);
    free_master_key_pair(&mkp);
    free(untrusted_ca_key);
    free(untrusted_ca_cert);
}

void test_public_key_extraction() {
    master_key_pair mkp;
    _verify(generate_master_key_pair(&mkp) == 0);
    char* csr_pem = NULL;
    _verify(generate_csr(&mkp, "pk_user@example.com", &csr_pem) == 0);

    char* ca_key = NULL, *ca_cert = NULL, *user_cert = NULL;
    _verify(generate_test_ca(&ca_key, &ca_cert) == 0);
    _verify(sign_csr_with_ca(&user_cert, csr_pem, ca_key, ca_cert) == 0);

    unsigned char extracted_pk[MASTER_PUBLIC_KEY_BYTES];
    _verify(extract_public_key_from_cert(user_cert, extracted_pk) == 0);

    _verify(sodium_memcmp(mkp.pk, extracted_pk, MASTER_PUBLIC_KEY_BYTES) == 0);

    free(ca_key);
    free(ca_cert);
    free(user_cert);
    free_csr_pem(csr_pem);
    free_master_key_pair(&mkp);
}


void run_all_tests() {
    printf("--- Running PKI Handler Module Tests ---\n");
    RUN_TEST(test_csr_generation);
    RUN_TEST(test_certificate_validation_successful);
    RUN_TEST(test_certificate_validation_failures);
    RUN_TEST(test_public_key_extraction);
    printf("--- Test Suite Finished ---\n");
}

int main() {
    // 【已添加】在所有操作之前进行初始化
    if (crypto_client_init() != 0) {
        printf("Fatal: Could not initialize crypto library for tests.\n");
        return 1;
    }
    if (pki_init() != 0) {
        printf("Fatal: Could not initialize PKI library for tests.\n");
        return 1;
    }

    run_all_tests();
    
    if (tests_failed > 0) {
        printf("\n\033[31mRESULT: %d/%d tests FAILED.\033[0m\n", tests_failed, tests_run);
        return 1;
    } else {
        printf("\n\033[32mRESULT: All %d tests PASSED.\033[0m\n", tests_run);
        return 0;
    }
}

// --- 辅助函数的实现 ---

int generate_test_ca(char** ca_key_pem, char** ca_cert_pem) {
    int ret = -1;
    EVP_PKEY* pkey = NULL;
    X509* cert = NULL;
    BIO* key_bio = NULL;
    BIO* cert_bio = NULL;

    unsigned char dummy_key[32];
    memset(dummy_key, 0xAA, 32);

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, dummy_key, 32);
    if (!pkey) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    cert = X509_new();
    if (!cert) goto cleanup;

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 31536000L); // 1 year
    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"Test System Root CA", -1, -1, 0);
    X509_set_issuer_name(cert, name);

    // 【已修正】对于 Ed25519, 签名函数的最后一个参数 (摘要算法) 必须为 NULL
    if (!X509_sign(cert, pkey, NULL)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

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
    if(pkey) EVP_PKEY_free(pkey);
    if(cert) X509_free(cert);
    if(key_bio) BIO_free(key_bio);
    if(cert_bio) BIO_free(cert_bio);
    return ret;
}

int sign_csr_with_ca(char** user_cert_pem, const char* csr_pem, const char* ca_key_pem, const char* ca_cert_pem) {
    int ret = -1;
    BIO *csr_bio = NULL, *ca_key_bio = NULL, *ca_cert_bio = NULL, *out_bio = NULL;
    X509_REQ *req = NULL;
    EVP_PKEY *ca_key = NULL;
    X509 *ca_cert = NULL, *user_cert = NULL;

    if (!csr_pem || !ca_key_pem || !ca_cert_pem) return -1;

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

    X509_set_version(user_cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(user_cert), 2);
    X509_set_issuer_name(user_cert, X509_get_subject_name(ca_cert));
    X509_gmtime_adj(X509_getm_notBefore(user_cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(user_cert), 31536000L);
    X509_set_subject_name(user_cert, X509_REQ_get_subject_name(req));
    EVP_PKEY* req_pubkey = X509_REQ_get_pubkey(req);
    X509_set_pubkey(user_cert, req_pubkey);
    EVP_PKEY_free(req_pubkey);
    
    // 【已修正】对于 Ed25519, 签名函数的最后一个参数 (摘要算法) 必须为 NULL
    if (X509_sign(user_cert, ca_key, NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

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