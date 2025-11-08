#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

// 包含我们需要测试的模块的头文件
#include "core_crypto/crypto_client.h"
#include "common/secure_memory.h"

// --- 测试框架宏 ---
int tests_run = 0;
int tests_failed = 0;

#define FAIL() printf("\033[31m[FAIL]\033[0m %s:%d\n", __FILE__, __LINE__)
#define _assert(test) do { if (!(test)) { FAIL(); tests_failed++; return; } } while(0)
#define _verify(test) do { _assert(test); } while(0)

// 将 RUN_TEST 宏更新为健壮的版本。
// 这个版本会在运行测试函数前后比较失败计数器，只有在计数器未增加时才打印 [PASS]。
#define RUN_TEST(test) do { \
    printf("  Running test: %s...", #test); \
    int prev_fails = tests_failed; \
    test(); \
    tests_run++; \
    if(tests_failed == prev_fails) printf("\033[32m [PASS]\033[0m\n"); \
} while(0)

// --- 测试用例 ---

void test_initialization() {
    _verify(crypto_client_init() == 0);
}

void test_key_generation() {
    master_key_pair mkp;
    _verify(generate_master_key_pair(&mkp) == 0);
    _verify(mkp.sk != NULL);

    recovery_key rk;
    _verify(generate_recovery_key(&rk) == 0);
    _verify(rk.key != NULL);

    free_master_key_pair(&mkp);
    free_recovery_key(&rk);
}

void test_argon2id_param_validation() {
    // 测试有效参数
    _verify(validate_argon2id_params(MIN_ARGON2ID_OPSLIMIT, MIN_ARGON2ID_MEMLIMIT) == true);
    _verify(validate_argon2id_params(MIN_ARGON2ID_OPSLIMIT + 1, MIN_ARGON2ID_MEMLIMIT) == true);

    // 测试无效参数 (抗降级)
    _verify(validate_argon2id_params(MIN_ARGON2ID_OPSLIMIT - 1, MIN_ARGON2ID_MEMLIMIT) == false);
    _verify(validate_argon2id_params(MIN_ARGON2ID_OPSLIMIT, MIN_ARGON2ID_MEMLIMIT - 1) == false);
}

void test_key_derivation_determinism() {
    unsigned char salt[USER_SALT_BYTES];
    memset(salt, 0x11, sizeof(salt));
    unsigned char pepper[16];
    memset(pepper, 0x22, sizeof(pepper));
    const char* password = "test_password";

    unsigned char* key1 = secure_alloc(SESSION_KEY_BYTES);
    unsigned char* key2 = secure_alloc(SESSION_KEY_BYTES);

    _verify(derive_key_from_password(key1, SESSION_KEY_BYTES, password, salt, MIN_ARGON2ID_OPSLIMIT, MIN_ARGON2ID_MEMLIMIT, pepper, sizeof(pepper)) == 0);
    _verify(derive_key_from_password(key2, SESSION_KEY_BYTES, password, salt, MIN_ARGON2ID_OPSLIMIT, MIN_ARGON2ID_MEMLIMIT, pepper, sizeof(pepper)) == 0);

    // 相同输入必须产生相同的密钥
    _verify(sodium_memcmp(key1, key2, SESSION_KEY_BYTES) == 0);
    
    // 改变 salt 会产生不同的密钥
    salt[0] = 0x12;
    _verify(derive_key_from_password(key2, SESSION_KEY_BYTES, password, salt, MIN_ARGON2ID_OPSLIMIT, MIN_ARGON2ID_MEMLIMIT, pepper, sizeof(pepper)) == 0);
    _verify(sodium_memcmp(key1, key2, SESSION_KEY_BYTES) != 0);

    secure_free(key1);
    secure_free(key2);
}

void test_encryption_decryption_roundtrip() {
    unsigned char key[SESSION_KEY_BYTES];
    randombytes_buf(key, sizeof(key));

    const char* message = "This is a secret message.";
    size_t message_len = strlen(message);

    size_t ciphertext_buf_len = message_len + crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    unsigned char* ciphertext = malloc(ciphertext_buf_len);
    unsigned long long ciphertext_len;

    _verify(encrypt_symmetric_aead(ciphertext, &ciphertext_len, (const unsigned char*)message, message_len, key) == 0);

    unsigned char* decrypted_message = malloc(message_len);
    unsigned long long decrypted_len;

    _verify(decrypt_symmetric_aead(decrypted_message, &decrypted_len, ciphertext, ciphertext_len, key) == 0);

    // 验证解密后的数据
    _verify(decrypted_len == message_len);
    _verify(memcmp(message, decrypted_message, message_len) == 0);

    free(ciphertext);
    free(decrypted_message);
}

void test_decryption_failure_wrong_key() {
    unsigned char key1[SESSION_KEY_BYTES];
    randombytes_buf(key1, sizeof(key1));
    unsigned char key2[SESSION_KEY_BYTES];
    randombytes_buf(key2, sizeof(key2)); // 不同的密钥

    const char* message = "Another secret.";
    size_t message_len = strlen(message);

    size_t ciphertext_buf_len = message_len + crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    unsigned char* ciphertext = malloc(ciphertext_buf_len);
    unsigned long long ciphertext_len;

    _verify(encrypt_symmetric_aead(ciphertext, &ciphertext_len, (const unsigned char*)message, message_len, key1) == 0);
    
    unsigned char* decrypted_message = malloc(message_len);
    unsigned long long decrypted_len;

    // 使用错误的密钥 key2 进行解密，必须失败
    _verify(decrypt_symmetric_aead(decrypted_message, &decrypted_len, ciphertext, ciphertext_len, key2) != 0);
    
    free(ciphertext);
    free(decrypted_message);
}


void test_decryption_failure_tampered_ciphertext() {
    unsigned char key[SESSION_KEY_BYTES];
    randombytes_buf(key, sizeof(key));

    const char* message = "Untampered data.";
    size_t message_len = strlen(message);

    size_t ciphertext_buf_len = message_len + crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    unsigned char* ciphertext = malloc(ciphertext_buf_len);
    unsigned long long ciphertext_len;

    _verify(encrypt_symmetric_aead(ciphertext, &ciphertext_len, (const unsigned char*)message, message_len, key) == 0);
    
    // 篡改密文的一个字节
    // 我们选择篡改 nonce 之后，MAC 标签之前的密文部分
    size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    if (ciphertext_len > nonce_len) {
        ciphertext[nonce_len] ^= 0x01; // Flip a bit
    }

    unsigned char* decrypted_message = malloc(message_len);
    unsigned long long decrypted_len;

    // 解密被篡改的数据，必须失败
    _verify(decrypt_symmetric_aead(decrypted_message, &decrypted_len, ciphertext, ciphertext_len, key) != 0);
    
    free(ciphertext);
    free(decrypted_message);
}

void run_all_tests() {
    printf("--- Running Core Crypto Module Tests ---\n");
    RUN_TEST(test_initialization);
    RUN_TEST(test_key_generation);
    RUN_TEST(test_argon2id_param_validation);
    RUN_TEST(test_key_derivation_determinism);
    RUN_TEST(test_encryption_decryption_roundtrip);
    RUN_TEST(test_decryption_failure_wrong_key);
    RUN_TEST(test_decryption_failure_tampered_ciphertext);
    printf("--- Test Suite Finished ---\n");
}

int main() {
    // 必须先初始化库才能运行测试
    if (crypto_client_init() != 0) {
        printf("Fatal: Could not initialize crypto library for tests.\n");
        return 1;
    }

    run_all_tests();
    
    // 更新最终的报告信息，使其更准确地报告失败的断言总数。
    if (tests_failed > 0) {
        printf("\n\033[31mRESULT: %d assertion(s) FAILED across all tests.\033[0m\n", tests_failed);
        return 1;
    } else {
        printf("\n\033[32mRESULT: All %d test functions PASSED.\033[0m\n", tests_run);
        return 0;
    }
}