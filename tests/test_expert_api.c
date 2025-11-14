// tests/test_expert_api.c
// This file tests the new, expert-level public API functions.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "hsc_kernel.h"
#include <sodium.h> // Needed for validation of key conversion

// --- 测试框架宏 ---
int tests_run = 0;
int tests_failed = 0;

#define FAIL() printf("\033[31m[FAIL]\033[0m %s:%d\n", __FILE__, __LINE__)
#define _assert(test) do { if (!(test)) { FAIL(); tests_failed++; return; } } while(0)
#define RUN_TEST(test) do { \
    printf("  Running test: %s...", #test); \
    int prev_fails = tests_failed; \
    test(); \
    tests_run++; \
    if(tests_failed == prev_fails) printf("\033[32m [PASS]\033[0m\n"); \
} while(0)


// --- 测试用例 ---

void test_api_kdf_deterministic() {
    unsigned char salt[HSC_KDF_SALT_BYTES];
    memset(salt, 0xAB, sizeof(salt));
    const char* password = "password_for_expert_kdf";

    unsigned char key1[HSC_SESSION_KEY_BYTES];
    unsigned char key2[HSC_SESSION_KEY_BYTES];

    // 第一次派生
    _assert(hsc_derive_key_from_password(key1, sizeof(key1), password, salt) == HSC_OK);
    
    // 使用完全相同的参数再次派生
    _assert(hsc_derive_key_from_password(key2, sizeof(key2), password, salt) == HSC_OK);
    
    // 验证确定性：结果必须相同
    _assert(sodium_memcmp(key1, key2, sizeof(key1)) == 0);
    
    // 改变 salt，再次派生
    salt[0] ^= 0xFF;
    _assert(hsc_derive_key_from_password(key2, sizeof(key2), password, salt) == HSC_OK);
    
    // 验证敏感性：结果必须不同
    _assert(sodium_memcmp(key1, key2, sizeof(key1)) != 0);
}

void test_api_key_conversion_validation() {
    unsigned char ed25519_pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char ed25519_sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(ed25519_pk, ed25519_sk);

    unsigned char x25519_pk_from_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char x25519_sk[crypto_box_SECRETKEYBYTES];
    unsigned char x25519_pk_from_sk[crypto_box_PUBLICKEYBYTES];

    // 调用API进行转换
    _assert(hsc_convert_ed25519_pk_to_x25519_pk(x25519_pk_from_pk, ed25519_pk) == HSC_OK);
    _assert(hsc_convert_ed25519_sk_to_x25519_sk(x25519_sk, ed25519_sk) == HSC_OK);

    // 独立验证：从转换后的X25519私钥推导出其对应的公钥
    _assert(crypto_scalarmult_base(x25519_pk_from_sk, x25519_sk) == 0);

    // 交叉验证：两种方式得到的X25519公钥必须完全一致
    _assert(sodium_memcmp(x25519_pk_from_pk, x25519_pk_from_sk, crypto_box_PUBLICKEYBYTES) == 0);
}

void test_api_aead_detached_roundtrip() {
    unsigned char key[HSC_SESSION_KEY_BYTES];
    unsigned char nonce[HSC_AEAD_NONCE_BYTES];
    hsc_random_bytes(key, sizeof(key));
    hsc_random_bytes(nonce, sizeof(nonce));

    const char* message = "Detached mode test message.";
    const char* ad = "Authenticated Additional Data";
    size_t message_len = strlen(message);
    size_t ad_len = strlen(ad);

    unsigned char ciphertext[200];
    unsigned char tag[HSC_AEAD_TAG_BYTES];
    unsigned char decrypted_message[200];

    // 加密
    int res_enc = hsc_aead_encrypt_detached(ciphertext, tag, (unsigned char*)message, message_len, (unsigned char*)ad, ad_len, nonce, key);
    _assert(res_enc == HSC_OK);

    // 解密
    int res_dec = hsc_aead_decrypt_detached(decrypted_message, ciphertext, message_len, tag, (unsigned char*)ad, ad_len, nonce, key);
    _assert(res_dec == HSC_OK);

    // 验证
    _assert(memcmp(message, decrypted_message, message_len) == 0);
}

void test_api_aead_detached_tampered() {
    unsigned char key[HSC_SESSION_KEY_BYTES];
    unsigned char nonce[HSC_AEAD_NONCE_BYTES];
    hsc_random_bytes(key, sizeof(key));
    hsc_random_bytes(nonce, sizeof(nonce));

    const char* message = "Another test message.";
    const char* ad = "Some AD";
    size_t message_len = strlen(message);
    size_t ad_len = strlen(ad);

    unsigned char ciphertext[200];
    unsigned char tag[HSC_AEAD_TAG_BYTES];
    unsigned char decrypted_message[200];
    
    _assert(hsc_aead_encrypt_detached(ciphertext, tag, (unsigned char*)message, message_len, (unsigned char*)ad, ad_len, nonce, key) == HSC_OK);
    
    // 1. 测试篡改密文
    ciphertext[0] ^= 0xFF;
    int res_dec_tamper_ct = hsc_aead_decrypt_detached(decrypted_message, ciphertext, message_len, tag, (unsigned char*)ad, ad_len, nonce, key);
    _assert(res_dec_tamper_ct == HSC_ERROR_CRYPTO_OPERATION);
    ciphertext[0] ^= 0xFF; // 恢复

    // 2. 测试篡改认证标签
    tag[0] ^= 0xFF;
    int res_dec_tamper_tag = hsc_aead_decrypt_detached(decrypted_message, ciphertext, message_len, tag, (unsigned char*)ad, ad_len, nonce, key);
    _assert(res_dec_tamper_tag == HSC_ERROR_CRYPTO_OPERATION);
    tag[0] ^= 0xFF; // 恢复

    // 3. 测试使用错误的附加数据
    const char* bad_ad = "Wrong AD";
    int res_dec_wrong_ad = hsc_aead_decrypt_detached(decrypted_message, ciphertext, message_len, tag, (unsigned char*)bad_ad, strlen(bad_ad), nonce, key);
    _assert(res_dec_wrong_ad == HSC_ERROR_CRYPTO_OPERATION);
}

void test_api_expert_null_arguments() {
    unsigned char dummy_buf[64];
    // [COMMITTEE FIX] Initialize the dummy buffer to a known state to satisfy the compiler.
    memset(dummy_buf, 0, sizeof(dummy_buf));

    // hsc_derive_key_from_password
    _assert(hsc_derive_key_from_password(NULL, 32, "pass", dummy_buf) == HSC_ERROR_INVALID_ARGUMENT);
    _assert(hsc_derive_key_from_password(dummy_buf, 32, NULL, dummy_buf) == HSC_ERROR_INVALID_ARGUMENT);
    _assert(hsc_derive_key_from_password(dummy_buf, 32, "pass", NULL) == HSC_ERROR_INVALID_ARGUMENT);

    // hsc_convert_ed25519_pk_to_x25519_pk
    _assert(hsc_convert_ed25519_pk_to_x25519_pk(NULL, dummy_buf) == HSC_ERROR_INVALID_ARGUMENT);
    _assert(hsc_convert_ed25519_pk_to_x25519_pk(dummy_buf, NULL) == HSC_ERROR_INVALID_ARGUMENT);
    
    // hsc_convert_ed25519_sk_to_x25519_sk
    _assert(hsc_convert_ed25519_sk_to_x25519_sk(NULL, dummy_buf) == HSC_ERROR_INVALID_ARGUMENT);
    _assert(hsc_convert_ed25519_sk_to_x25519_sk(dummy_buf, NULL) == HSC_ERROR_INVALID_ARGUMENT);
    
    // hsc_aead_encrypt_detached
    _assert(hsc_aead_encrypt_detached(NULL, dummy_buf, dummy_buf, 1, NULL, 0, dummy_buf, dummy_buf) == HSC_ERROR_INVALID_ARGUMENT);
    _assert(hsc_aead_encrypt_detached(dummy_buf, NULL, dummy_buf, 1, NULL, 0, dummy_buf, dummy_buf) == HSC_ERROR_INVALID_ARGUMENT);
    // ... (可以为每个参数都添加测试)
    _assert(hsc_aead_encrypt_detached(dummy_buf, dummy_buf, dummy_buf, 1, NULL, 0, NULL, dummy_buf) == HSC_ERROR_INVALID_ARGUMENT);
    _assert(hsc_aead_encrypt_detached(dummy_buf, dummy_buf, dummy_buf, 1, NULL, 0, dummy_buf, NULL) == HSC_ERROR_INVALID_ARGUMENT);

    // hsc_aead_decrypt_detached
    _assert(hsc_aead_decrypt_detached(NULL, dummy_buf, 1, dummy_buf, NULL, 0, dummy_buf, dummy_buf) == HSC_ERROR_INVALID_ARGUMENT);
    // ... (可以为每个参数都添加测试)
    _assert(hsc_aead_decrypt_detached(dummy_buf, dummy_buf, 1, NULL, NULL, 0, dummy_buf, dummy_buf) == HSC_ERROR_INVALID_ARGUMENT);
}


void run_all_tests() {
    printf("--- Running Expert-Level API Test Suite ---\n");
    RUN_TEST(test_api_kdf_deterministic);
    RUN_TEST(test_api_key_conversion_validation);
    RUN_TEST(test_api_aead_detached_roundtrip);
    RUN_TEST(test_api_aead_detached_tampered);
    RUN_TEST(test_api_expert_null_arguments);
    printf("--- Test Suite Finished ---\n");
}

int main() {
    if (hsc_init() != HSC_OK) {
        printf("Fatal: Could not initialize hsc_kernel for tests.\n");
        return 1;
    }

    run_all_tests();
    
    hsc_cleanup();

    if (tests_failed > 0) {
        printf("\n\033[31mRESULT: %d assertion(s) FAILED in expert API tests.\033[0m\n", tests_failed);
        return 1;
    } else {
        printf("\n\033[32mRESULT: All %d expert API test functions PASSED.\033[0m\n", tests_run);
        return 0;
    }
}