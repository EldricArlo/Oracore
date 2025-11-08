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

// --- 测试辅助宏 ---
#define TEST_ASSERT(condition, message) do { \
    if (!(condition)) { \
        fprintf(stderr, "TEST FAILED: %s (%s:%d)\n", message, __FILE__, __LINE__); \
        return -1; \
    } \
} while(0)

// --- 更高级的测试辅助函数 ---

// 辅助函数，用于创建具有特定时间偏移的证书，以测试有效期
int sign_csr_with_ca_timed(char** user_cert_pem, const char* csr_pem, 
                           const char* ca_key_pem, const char* ca_cert_pem,
                           long not_before_offset_sec, long not_after_offset_sec) {
    int ret = -1;
    BIO *csr_bio = NULL, *ca_key_bio = NULL, *ca_cert_bio = NULL, *out_bio = NULL;
    X509_REQ *req = NULL;
    EVP_PKEY *ca_key = NULL;
    X509 *ca_cert = NULL, *user_cert = NULL;

    csr_bio = BIO_new_mem_buf(csr_pem, -1);
    ca_key_bio = BIO_new_mem_buf(ca_key_pem, -1);
    ca_cert_bio = BIO_new_mem_buf(ca_cert_pem, -1);
    req = PEM_read_bio_X509_REQ(csr_bio, NULL, NULL, NULL);
    ca_key = PEM_read_bio_PrivateKey(ca_key_bio, NULL, NULL, NULL);
    ca_cert = PEM_read_bio_X509(ca_cert_bio, NULL, NULL, NULL);
    user_cert = X509_new();

    if (!req || !ca_key || !ca_cert || !user_cert) goto cleanup;

    X509_set_version(user_cert, 2L);
    ASN1_INTEGER_set(X509_get_serialNumber(user_cert), randombytes_random());
    X509_set_issuer_name(user_cert, X509_get_subject_name(ca_cert));

    // -- 时间控制 --
    X509_gmtime_adj(X509_getm_notBefore(user_cert), not_before_offset_sec);
    X509_gmtime_adj(X509_getm_notAfter(user_cert), not_after_offset_sec);
    
    EVP_PKEY* req_pubkey = X509_REQ_get_pubkey(req);
    X509_set_subject_name(user_cert, X509_REQ_get_subject_name(req));
    X509_set_pubkey(user_cert, req_pubkey);
    EVP_PKEY_free(req_pubkey);
    
    // 为OCSP测试添加AIA扩展
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, NULL, NID_info_access, "OCSP;URI:http://127.0.0.1:8888");
    X509_add_ext(user_cert, ex, -1);
    X509_EXTENSION_free(ex);
    
    if (X509_sign(user_cert, ca_key, NULL) <= 0) goto cleanup;

    out_bio = BIO_new(BIO_s_mem());
    if(!out_bio || !PEM_write_bio_X509(out_bio, user_cert)) goto cleanup;
    
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

// 外部的CA证书生成函数，内容与pki_lifecycle测试文件中的相同
int generate_test_ca(char** ca_key_pem, char** ca_cert_pem);

// --- 测试用例 ---

// 测试“正常路径”：一个完全有效的证书应该验证成功（除OCSP外）
int test_verification_successful_path() {
    printf("  Running test: test_verification_successful_path...\n");
    char* ca_key = NULL, *ca_cert = NULL, *user_csr = NULL, *user_cert = NULL;
    master_key_pair user_kp;
    user_kp.sk = NULL;
    const char* username = "valid.user@test.com";

    TEST_ASSERT(generate_test_ca(&ca_key, &ca_cert) == 0, "CA generation failed");
    TEST_ASSERT(generate_master_key_pair(&user_kp) == 0, "User keygen failed");
    TEST_ASSERT(generate_csr(&user_kp, username, &user_csr) == 0, "CSR gen failed");
    // 证书有效期为1年
    TEST_ASSERT(sign_csr_with_ca_timed(&user_cert, user_csr, ca_key, ca_cert, 0, 31536000L) == 0, "Cert signing failed");

    // 注意：我们预期OCSP会失败，因为测试服务器不存在。这是在验证“故障关闭”策略。
    int res = verify_user_certificate(user_cert, ca_cert, username);
    TEST_ASSERT(res == -4, "Verification must fail with OCSP error (-4) for non-existent responder");

    free(ca_key); free(ca_cert); free(user_csr); free(user_cert);
    free_master_key_pair(&user_kp);
    printf("    ... PASSED\n");
    return 0;
}

// 测试由不受信任的CA签发的证书，预期失败
int test_verification_untrusted_ca() {
    printf("  Running test: test_verification_untrusted_ca...\n");
    char* ca1_key = NULL, *ca1_cert = NULL; // 我们信任的CA
    char* ca2_key = NULL, *ca2_cert = NULL; // 不受信任的CA
    char* user_csr = NULL, *user_cert = NULL;
    master_key_pair user_kp;
    user_kp.sk = NULL;

    TEST_ASSERT(generate_test_ca(&ca1_key, &ca1_cert) == 0, "CA 1 generation failed");
    TEST_ASSERT(generate_test_ca(&ca2_key, &ca2_cert) == 0, "CA 2 generation failed");
    TEST_ASSERT(generate_master_key_pair(&user_kp) == 0, "User keygen failed");
    TEST_ASSERT(generate_csr(&user_kp, "user", &user_csr) == 0, "CSR gen failed");
    
    // 证书由 *不受信任的* CA2 签发
    TEST_ASSERT(sign_csr_with_ca_timed(&user_cert, user_csr, ca2_key, ca2_cert, 0, 31536000L) == 0, "Cert signing failed");

    // 但我们使用 *受信任的* CA1 来验证，这必须失败
    int res = verify_user_certificate(user_cert, ca1_cert, "user");
    TEST_ASSERT(res == -2, "Verification with untrusted CA must fail with chain/signature error (-2)");

    free(ca1_key); free(ca1_cert); free(ca2_key); free(ca2_cert);
    free(user_csr); free(user_cert);
    free_master_key_pair(&user_kp);
    printf("    ... PASSED\n");
    return 0;
}

// 测试证书主体名称不匹配，预期失败
int test_verification_subject_mismatch() {
    printf("  Running test: test_verification_subject_mismatch...\n");
    char* ca_key = NULL, *ca_cert = NULL, *user_csr = NULL, *user_cert = NULL;
    master_key_pair user_kp;
    user_kp.sk = NULL;
    const char* actual_username = "alice";
    const char* expected_username = "bob"; // 期望的用户是 bob

    TEST_ASSERT(generate_test_ca(&ca_key, &ca_cert) == 0, "CA generation failed");
    TEST_ASSERT(generate_master_key_pair(&user_kp) == 0, "User keygen failed");
    TEST_ASSERT(generate_csr(&user_kp, actual_username, &user_csr) == 0, "CSR gen failed");
    TEST_ASSERT(sign_csr_with_ca_timed(&user_cert, user_csr, ca_key, ca_cert, 0, 31536000L) == 0, "Cert signing failed");

    // 验证时期望找到 bob，但证书是为 alice 颁发的
    int res = verify_user_certificate(user_cert, ca_cert, expected_username);
    TEST_ASSERT(res == -3, "Verification with wrong subject name must fail with subject mismatch error (-3)");

    free(ca_key); free(ca_cert); free(user_csr); free(user_cert);
    free_master_key_pair(&user_kp);
    printf("    ... PASSED\n");
    return 0;
}

// 测试已过期的证书，预期失败
int test_verification_expired_cert() {
    printf("  Running test: test_verification_expired_cert...\n");
    char* ca_key = NULL, *ca_cert = NULL, *user_csr = NULL, *user_cert = NULL;
    master_key_pair user_kp;
    user_kp.sk = NULL;

    TEST_ASSERT(generate_test_ca(&ca_key, &ca_cert) == 0, "CA generation failed");
    TEST_ASSERT(generate_master_key_pair(&user_kp) == 0, "User keygen failed");
    TEST_ASSERT(generate_csr(&user_kp, "user", &user_csr) == 0, "CSR gen failed");
    
    // 创建一个已过期的证书 (有效期从2秒前开始，1秒前结束)
    TEST_ASSERT(sign_csr_with_ca_timed(&user_cert, user_csr, ca_key, ca_cert, -2, -1) == 0, "Expired cert signing failed");

    int res = verify_user_certificate(user_cert, ca_cert, "user");
    TEST_ASSERT(res == -2, "Verification of expired certificate must fail with validity error (-2)");

    free(ca_key); free(ca_cert); free(user_csr); free(user_cert);
    free_master_key_pair(&user_kp);
    printf("    ... PASSED\n");
    return 0;
}

// 测试尚未生效的证书，预期失败
int test_verification_not_yet_valid_cert() {
    printf("  Running test: test_verification_not_yet_valid_cert...\n");
    char* ca_key = NULL, *ca_cert = NULL, *user_csr = NULL, *user_cert = NULL;
    master_key_pair user_kp;
    user_kp.sk = NULL;

    TEST_ASSERT(generate_test_ca(&ca_key, &ca_cert) == 0, "CA generation failed");
    TEST_ASSERT(generate_master_key_pair(&user_kp) == 0, "User keygen failed");
    TEST_ASSERT(generate_csr(&user_kp, "user", &user_csr) == 0, "CSR gen failed");
    
    // 创建一个尚未生效的证书 (有效期从1小时后开始)
    TEST_ASSERT(sign_csr_with_ca_timed(&user_cert, user_csr, ca_key, ca_cert, 3600, 3600 + 31536000L) == 0, "Future cert signing failed");

    int res = verify_user_certificate(user_cert, ca_cert, "user");
    TEST_ASSERT(res == -2, "Verification of not-yet-valid certificate must fail with validity error (-2)");

    free(ca_key); free(ca_cert); free(user_csr); free(user_cert);
    free_master_key_pair(&user_kp);
    printf("    ... PASSED\n");
    return 0;
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

// --- 辅助函数 generate_test_ca 的实现 ---
// (该函数与 test_pki_lifecycle.c 中的版本完全相同)
int generate_test_ca(char** ca_key_pem, char** ca_cert_pem) {
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

    // X509 V3 extensions
    X509_EXTENSION *ex_bc = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
    X509_EXTENSION *ex_ku = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "critical,digitalSignature,keyCertSign,cRLSign");
    X509_EXTENSION *ex_ski = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_key_identifier, "hash");
    X509_add_ext(cert, ex_bc, -1);
    X509_add_ext(cert, ex_ku, -1);
    X509_add_ext(cert, ex_ski, -1);
    X509_EXTENSION_free(ex_bc); X509_EXTENSION_free(ex_ku); X509_EXTENSION_free(ex_ski);

    if (!X509_sign(cert, pkey, NULL)) goto cleanup;

    key_bio = BIO_new(BIO_s_mem());
    cert_bio = BIO_new(BIO_s_mem());
    if(!key_bio || !cert_bio || !PEM_write_bio_PrivateKey(key_bio, pkey, NULL, NULL, 0, NULL, NULL) || !PEM_write_bio_X509(cert_bio, cert)) goto cleanup;
    
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