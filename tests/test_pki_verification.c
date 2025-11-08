// tests/test_pki_verification.c

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#include "core_crypto/crypto_client.h"
#include "pki/pki_handler.h"

// [委员会修改] 移除了原有的 TEST_ASSERT 宏。

// --- 更高级的测试辅助函数 ---

// [委员会修正] 增加 seed_byte 参数
int generate_test_ca(char** ca_key_pem, char** ca_cert_pem, unsigned char seed_byte);

int sign_csr_with_ca_timed(char** user_cert_pem, const char* csr_pem, 
                           const char* ca_key_pem, const char* ca_cert_pem,
                           long not_before_offset_sec, long not_after_offset_sec);


// --- 测试用例 ---

int test_verification_successful_path() {
    printf("  Running test: test_verification_successful_path...\n");
    int ret = -1;
    char* ca_key = NULL, *ca_cert = NULL, *user_csr = NULL, *user_cert = NULL;
    master_key_pair user_kp = { .sk = NULL };
    const char* username = "valid.user@test.com";

    // [修正] 使用种子 0xAA
    if (generate_test_ca(&ca_key, &ca_cert, 0xAA) != 0) goto cleanup;
    if (generate_master_key_pair(&user_kp) != 0) goto cleanup;
    if (generate_csr(&user_kp, username, &user_csr) != 0) goto cleanup;
    if (sign_csr_with_ca_timed(&user_cert, user_csr, ca_key, ca_cert, 0, 31536000L) != 0) goto cleanup;

    int res = verify_user_certificate(user_cert, ca_cert, username);
    if (res != -4) {
        fprintf(stderr, "TEST FAILED: Verification must fail with OCSP error (-4), but got %d (%s:%d)\n", res, __FILE__, __LINE__);
        goto cleanup;
    }

    ret = 0;
    printf("    ... PASSED\n");

cleanup:
    free(ca_key); free(ca_cert); free(user_csr); free(user_cert);
    free_master_key_pair(&user_kp);
    return ret;
}

int test_verification_untrusted_ca() {
    printf("  Running test: test_verification_untrusted_ca...\n");
    int ret = -1;
    char* ca1_key = NULL, *ca1_cert = NULL;
    char* ca2_key = NULL, *ca2_cert = NULL;
    char* user_csr = NULL, *user_cert = NULL;
    master_key_pair user_kp = { .sk = NULL };

    // [修正] 使用不同的种子生成两个不同的CA
    if (generate_test_ca(&ca1_key, &ca1_cert, 0xBB) != 0) goto cleanup; // Trusted CA
    if (generate_test_ca(&ca2_key, &ca2_cert, 0xCC) != 0) goto cleanup; // Untrusted CA

    if (generate_master_key_pair(&user_kp) != 0) goto cleanup;
    if (generate_csr(&user_kp, "user", &user_csr) != 0) goto cleanup;
    
    // 使用“不受信任”的 CA2 签署
    if (sign_csr_with_ca_timed(&user_cert, user_csr, ca2_key, ca2_cert, 0, 31536000L) != 0) goto cleanup;

    // 使用“受信任”的 CA1 验证, 必须失败
    int res = verify_user_certificate(user_cert, ca1_cert, "user");
    if (res != -2) {
        fprintf(stderr, "TEST FAILED: Verification with untrusted CA must fail with chain/signature error (-2), but got %d (%s:%d)\n", res, __FILE__, __LINE__);
        goto cleanup;
    }

    ret = 0;
    printf("    ... PASSED\n");

cleanup:
    free(ca1_key); free(ca1_cert); free(ca2_key); free(ca2_cert);
    free(user_csr); free(user_cert);
    free_master_key_pair(&user_kp);
    return ret;
}

int test_verification_subject_mismatch() {
    printf("  Running test: test_verification_subject_mismatch...\n");
    int ret = -1;
    char* ca_key = NULL, *ca_cert = NULL, *user_csr = NULL, *user_cert = NULL;
    master_key_pair user_kp = { .sk = NULL };
    const char* actual_username = "alice";
    const char* expected_username = "bob";

    // [修正] 使用种子 0xDD
    if (generate_test_ca(&ca_key, &ca_cert, 0xDD) != 0) goto cleanup;
    if (generate_master_key_pair(&user_kp) != 0) goto cleanup;
    if (generate_csr(&user_kp, actual_username, &user_csr) != 0) goto cleanup;
    if (sign_csr_with_ca_timed(&user_cert, user_csr, ca_key, ca_cert, 0, 31536000L) != 0) goto cleanup;

    int res = verify_user_certificate(user_cert, ca_cert, expected_username);
    if (res != -3) {
        fprintf(stderr, "TEST FAILED: Verification with wrong subject name must fail with subject mismatch error (-3), but got %d (%s:%d)\n", res, __FILE__, __LINE__);
        goto cleanup;
    }

    ret = 0;
    printf("    ... PASSED\n");

cleanup:
    free(ca_key); free(ca_cert); free(user_csr); free(user_cert);
    free_master_key_pair(&user_kp);
    return ret;
}

int test_verification_expired_cert() {
    printf("  Running test: test_verification_expired_cert...\n");
    int ret = -1;
    char* ca_key = NULL, *ca_cert = NULL, *user_csr = NULL, *user_cert = NULL;
    master_key_pair user_kp = { .sk = NULL };

    // [修正] 使用种子 0xEE
    if (generate_test_ca(&ca_key, &ca_cert, 0xEE) != 0) goto cleanup;
    if (generate_master_key_pair(&user_kp) != 0) goto cleanup;
    if (generate_csr(&user_kp, "user", &user_csr) != 0) goto cleanup;
    
    if (sign_csr_with_ca_timed(&user_cert, user_csr, ca_key, ca_cert, -2, -1) != 0) goto cleanup;

    int res = verify_user_certificate(user_cert, ca_cert, "user");
    if (res != -2) {
        fprintf(stderr, "TEST FAILED: Verification of expired certificate must fail with validity error (-2), but got %d (%s:%d)\n", res, __FILE__, __LINE__);
        goto cleanup;
    }

    ret = 0;
    printf("    ... PASSED\n");

cleanup:
    free(ca_key); free(ca_cert); free(user_csr); free(user_cert);
    free_master_key_pair(&user_kp);
    return ret;
}

int test_verification_not_yet_valid_cert() {
    printf("  Running test: test_verification_not_yet_valid_cert...\n");
    int ret = -1;
    char* ca_key = NULL, *ca_cert = NULL, *user_csr = NULL, *user_cert = NULL;
    master_key_pair user_kp = { .sk = NULL };

    // [修正] 使用种子 0xFF
    if (generate_test_ca(&ca_key, &ca_cert, 0xFF) != 0) goto cleanup;
    if (generate_master_key_pair(&user_kp) != 0) goto cleanup;
    if (generate_csr(&user_kp, "user", &user_csr) != 0) goto cleanup;
    
    if (sign_csr_with_ca_timed(&user_cert, user_csr, ca_key, ca_cert, 3600, 3600 + 31536000L) != 0) goto cleanup;

    int res = verify_user_certificate(user_cert, ca_cert, "user");
    if (res != -2) {
        fprintf(stderr, "TEST FAILED: Verification of not-yet-valid certificate must fail with validity error (-2), but got %d (%s:%d)\n", res, __FILE__, __LINE__);
        goto cleanup;
    }

    ret = 0;
    printf("    ... PASSED\n");

cleanup:
    free(ca_key); free(ca_cert); free(user_csr); free(user_cert);
    free_master_key_pair(&user_kp);
    return ret;
}


int main() {
    if (crypto_client_init() != 0 || pki_init() != 0) {
        fprintf(stderr, "Fatal: Library initialization failed\n");
        return 1;
    }

    printf("--- Running PKI Verification Test Suite ---\n");
    if (test_verification_successful_path() != 0) return 1;
    if (test_verification_untrusted_ca() != 0) return 1;
    if (test_verification_subject_mismatch() != 0) return 1;
    if (test_verification_expired_cert() != 0) return 1;
    if (test_verification_not_yet_valid_cert() != 0) return 1;
    
    printf("--- PKI Verification Test Suite: ALL PASSED ---\n\n");
    return 0;
}

// --- 辅助函数 的实现 ---
// (此处的 sign_csr_with_ca_timed 和下面的 generate_test_ca 与 test_pki_lifecycle.c 中的版本是重复的，但为了文件独立性而保留)

// [辅助函数] 签名CSR，并控制证书有效期
int sign_csr_with_ca_timed(char** user_cert_pem, const char* csr_pem, 
                           const char* ca_key_pem, const char* ca_cert_pem,
                           long not_before_offset_sec, long not_after_offset_sec) {
    // ... (函数实现不变)
    int ret = -1;
    BIO *csr_bio = NULL, *ca_key_bio = NULL, *ca_cert_bio = NULL, *out_bio = NULL;
    X509_REQ *req = NULL;
    EVP_PKEY *ca_key = NULL;
    X509 *ca_cert = NULL, *user_cert = NULL;
    EVP_PKEY* req_pubkey = NULL;

    csr_bio = BIO_new_mem_buf(csr_pem, -1);
    ca_key_bio = BIO_new_mem_buf(ca_key_pem, -1);
    ca_cert_bio = BIO_new_mem_buf(ca_cert_pem, -1);
    if (!csr_bio || !ca_key_bio || !ca_cert_bio) goto cleanup;
    req = PEM_read_bio_X509_REQ(csr_bio, NULL, NULL, NULL);
    ca_key = PEM_read_bio_PrivateKey(ca_key_bio, NULL, NULL, NULL);
    ca_cert = PEM_read_bio_X509(ca_cert_bio, NULL, NULL, NULL);
    user_cert = X509_new();
    if (!req || !ca_key || !ca_cert || !user_cert) goto cleanup;
    X509_set_version(user_cert, 2L);
    ASN1_INTEGER_set(X509_get_serialNumber(user_cert), randombytes_random());
    X509_set_issuer_name(user_cert, X509_get_subject_name(ca_cert));
    X509_gmtime_adj(X509_getm_notBefore(user_cert), not_before_offset_sec);
    X509_gmtime_adj(X509_getm_notAfter(user_cert), not_after_offset_sec);
    req_pubkey = X509_REQ_get_pubkey(req);
    X509_set_subject_name(user_cert, X509_REQ_get_subject_name(req));
    X509_set_pubkey(user_cert, req_pubkey);
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
    BIO_free(csr_bio); BIO_free(ca_key_bio); BIO_free(ca_cert_bio); BIO_free(out_bio);
    X509_REQ_free(req); EVP_PKEY_free(ca_key); X509_free(ca_cert); X509_free(user_cert);
    return ret;
}

// [辅助函数] 生成测试CA
int generate_test_ca(char** ca_key_pem, char** ca_cert_pem, unsigned char seed_byte) {
    // ... (函数实现与 test_pki_lifecycle.c 中修正后的一致)
    int ret = -1;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    BIO *key_bio = NULL, *cert_bio = NULL;
    unsigned char ca_sk_seed[crypto_sign_SEEDBYTES];
    memset(ca_sk_seed, seed_byte, sizeof(ca_sk_seed));
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
    X509_EXTENSION *ex_bc = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
    X509_EXTENSION *ex_ku = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "critical,digitalSignature,keyCertSign,cRLSign");
    X509_EXTENSION *ex_ski = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_key_identifier, "hash");
    if(ex_bc) X509_add_ext(cert, ex_bc, -1);
    if(ex_ku) X509_add_ext(cert, ex_ku, -1);
    if(ex_ski) X509_add_ext(cert, ex_ski, -1);
    X509_EXTENSION_free(ex_bc); X509_EXTENSION_free(ex_ku); X509_EXTENSION_free(ex_ski);
    if (!X509_sign(cert, pkey, NULL)) goto cleanup;
    key_bio = BIO_new(BIO_s_mem());
    cert_bio = BIO_new(BIO_s_mem());
    if(!key_bio || !cert_bio || !PEM_write_bio_PrivateKey(key_bio, pkey, NULL, NULL, 0, NULL, NULL) || !PEM_write_bio_X509(cert_bio, cert)) goto cleanup;
    BUF_MEM *key_mem, *cert_mem;
    BIO_get_mem_ptr(key_bio, &key_mem);
    *ca_key_pem = (char*)malloc(key_mem->length + 1);
    if (*ca_key_pem) {
        memcpy(*ca_key_pem, key_mem->data, key_mem->length);
        (*ca_key_pem)[key_mem->length] = '\0';
    } else {
        goto cleanup;
    }
    BIO_get_mem_ptr(cert_bio, &cert_mem);
    *ca_cert_pem = (char*)malloc(cert_mem->length + 1);
    if (*ca_cert_pem) {
        memcpy(*ca_cert_pem, cert_mem->data, cert_mem->length);
        (*ca_cert_pem)[cert_mem->length] = '\0';
    } else {
        free(*ca_key_pem);
        *ca_key_pem = NULL;
        goto cleanup;
    }
    ret = 0;
cleanup:
    EVP_PKEY_free(pkey); X509_free(cert); BIO_free(key_bio); BIO_free(cert_bio);
    return ret;
}