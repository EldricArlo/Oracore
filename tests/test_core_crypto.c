#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h> // 为 getenv 和 _putenv_s (Windows) / setenv (POSIX)

// 包含我们需要测试的模块的头文件
#include "core_crypto/crypto_client.h"
#include "common/secure_memory.h"

// --- [新增] 跨平台的环境变量设置辅助函数 ---
// 为了让测试代码在 Windows 和 POSIX 系统上都能运行，我们创建这些辅助函数。
#if defined(_WIN32) || defined(_WIN64)
// 在 Windows 上，我们使用 _putenv_s
static void test_setenv(const char *name, const char *value) {
    _putenv_s(name, value);
}
static void test_unsetenv(const char *name) {
    // 在 Windows 上，将环境变量设置为空字符串可以有效移除它
    _putenv_s(name, "");
}
#else
// 在 POSIX 系统 (Linux, macOS) 上，我们使用标准函数
static void test_setenv(const char *name, const char *value) {
    setenv(name, value, 1);
}
static void test_unsetenv(const char *name) {
    unsetenv(name);
}
#endif


// --- 测试框架宏 ---
int tests_run = 0;
int tests_failed = 0;

#define FAIL() printf("\033[31m[FAIL]\033[0m %s:%d\n", __FILE__, __LINE__)
#define _assert(test) do { if (!(test)) { FAIL(); tests_failed++; return; } } while(0)
#define _verify(test) do { _assert(test); } while(0)
#define RUN_TEST(test) do { \
    printf("  Running test: %s...", #test); \
    int prev_fails = tests_failed; \
    test(); \
    tests_run++; \
    if(tests_failed == prev_fails) printf("\033[32m [PASS]\033[0m\n"); \
} while(0)

// 声明外部全局变量，以便在测试中访问和验证它们
extern unsigned long long g_argon2_opslimit;
extern size_t g_argon2_memlimit;


// --- 测试用例 ---

void test_initialization() {
    // [FIX]: 适配新的 API 签名。
    // 我们使用显式传递 Pepper 的方式进行测试，验证 API 变更是否生效。
    const char* test_pepper = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    
    // 1. 测试显式传入 (应该成功)
    _verify(crypto_client_init(test_pepper) == 0);
    
    // 清理资源以便后续测试
    crypto_client_cleanup();
}

void test_key_generation() {
    // [修复] 初始化新的结构体成员，确保指针为 NULL
    master_key_pair mkp = { .identity_sk = NULL, .encryption_sk = NULL };
    
    _verify(generate_master_key_pair(&mkp) == 0);
    
    // [修复] 验证两个私钥都已分配
    _verify(mkp.identity_sk != NULL);
    _verify(mkp.encryption_sk != NULL);

    recovery_key rk;
    _verify(generate_recovery_key(&rk) == 0);
    _verify(rk.key != NULL);

    free_master_key_pair(&mkp);
    free_recovery_key(&rk);
}

void test_argon2id_baseline_validation() {
    _verify(validate_argon2id_params(BASELINE_ARGON2ID_OPSLIMIT, BASELINE_ARGON2ID_MEMLIMIT) == true);
    _verify(validate_argon2id_params(BASELINE_ARGON2ID_OPSLIMIT + 1, BASELINE_ARGON2ID_MEMLIMIT) == true);
    _verify(validate_argon2id_params(BASELINE_ARGON2ID_OPSLIMIT - 1, BASELINE_ARGON2ID_MEMLIMIT) == false);
    _verify(validate_argon2id_params(BASELINE_ARGON2ID_MEMLIMIT, BASELINE_ARGON2ID_MEMLIMIT - 1) == false);
}

void test_config_loading_from_env() {
    // 场景 1: 无环境变量，应使用编译时基线值
    test_unsetenv("HSC_ARGON2_OPSLIMIT"); // [修改] 使用辅助函数
    test_unsetenv("HSC_ARGON2_MEMLIMIT"); // [修改] 使用辅助函数
    g_argon2_opslimit = BASELINE_ARGON2ID_OPSLIMIT;
    g_argon2_memlimit = BASELINE_ARGON2ID_MEMLIMIT;
    crypto_config_load_from_env();
    _verify(g_argon2_opslimit == BASELINE_ARGON2ID_OPSLIMIT);
    _verify(g_argon2_memlimit == BASELINE_ARGON2ID_MEMLIMIT);

    // 场景 2: 设置有效且更高的环境变量
    test_setenv("HSC_ARGON2_OPSLIMIT", "10"); // [修改] 使用辅助函数
    test_setenv("HSC_ARGON2_MEMLIMIT", "300000000"); // [修改] 使用辅助函数
    crypto_config_load_from_env();
    _verify(g_argon2_opslimit == 10);
    _verify(g_argon2_memlimit == 300000000);

    // 场景 3: 设置低于基线的环境变量 (应被忽略)
    test_setenv("HSC_ARGON2_OPSLIMIT", "1");
    test_setenv("HSC_ARGON2_MEMLIMIT", "1024");
    g_argon2_opslimit = BASELINE_ARGON2ID_OPSLIMIT;
    g_argon2_memlimit = BASELINE_ARGON2ID_MEMLIMIT;
    crypto_config_load_from_env();
    _verify(g_argon2_opslimit == BASELINE_ARGON2ID_OPSLIMIT);
    _verify(g_argon2_memlimit == BASELINE_ARGON2ID_MEMLIMIT);

    // 场景 4: 设置格式错误的环境变量 (应被忽略)
    test_setenv("HSC_ARGON2_OPSLIMIT", "not_a_number");
    test_setenv("HSC_ARGON2_MEMLIMIT", "512M");
    g_argon2_opslimit = BASELINE_ARGON2ID_OPSLIMIT;
    g_argon2_memlimit = BASELINE_ARGON2ID_MEMLIMIT;
    crypto_config_load_from_env();
    _verify(g_argon2_opslimit == BASELINE_ARGON2ID_OPSLIMIT);
    _verify(g_argon2_memlimit == BASELINE_ARGON2ID_MEMLIMIT);

    // 清理环境变量
    test_unsetenv("HSC_ARGON2_OPSLIMIT");
    test_unsetenv("HSC_ARGON2_MEMLIMIT");
    crypto_config_load_from_env();
}

void test_key_derivation_determinism() {
    unsigned char salt[USER_SALT_BYTES];
    memset(salt, 0x11, sizeof(salt));
    unsigned char pepper[16];
    memset(pepper, 0x22, sizeof(pepper));
    const char* password = "test_password";

    unsigned char* key1 = secure_alloc(SESSION_KEY_BYTES);
    unsigned char* key2 = secure_alloc(SESSION_KEY_BYTES);

    _verify(derive_key_from_password(key1, SESSION_KEY_BYTES, password, salt, g_argon2_opslimit, g_argon2_memlimit, pepper, sizeof(pepper)) == 0);
    _verify(derive_key_from_password(key2, SESSION_KEY_BYTES, password, salt, g_argon2_opslimit, g_argon2_memlimit, pepper, sizeof(pepper)) == 0);
    _verify(sodium_memcmp(key1, key2, SESSION_KEY_BYTES) == 0);
    
    salt[0] = 0x12;
    _verify(derive_key_from_password(key2, SESSION_KEY_BYTES, password, salt, g_argon2_opslimit, g_argon2_memlimit, pepper, sizeof(pepper)) == 0);
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
    _verify(decrypted_len == message_len);
    _verify(memcmp(message, decrypted_message, message_len) == 0);
    free(ciphertext);
    free(decrypted_message);
}

void test_decryption_failure_wrong_key() {
    unsigned char key1[SESSION_KEY_BYTES];
    randombytes_buf(key1, sizeof(key1));
    unsigned char key2[SESSION_KEY_BYTES];
    randombytes_buf(key2, sizeof(key2));
    const char* message = "Another secret.";
    size_t message_len = strlen(message);
    size_t ciphertext_buf_len = message_len + crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    unsigned char* ciphertext = malloc(ciphertext_buf_len);
    unsigned long long ciphertext_len;
    _verify(encrypt_symmetric_aead(ciphertext, &ciphertext_len, (const unsigned char*)message, message_len, key1) == 0);
    unsigned char* decrypted_message = malloc(message_len);
    unsigned long long decrypted_len;
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
    size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    if (ciphertext_len > nonce_len) {
        ciphertext[nonce_len] ^= 0x01;
    }
    unsigned char* decrypted_message = malloc(message_len);
    unsigned long long decrypted_len;
    _verify(decrypt_symmetric_aead(decrypted_message, &decrypted_len, ciphertext, ciphertext_len, key) != 0);
    free(ciphertext);
    free(decrypted_message);
}

void run_all_tests() {
    printf("--- Running Core Crypto Module Tests ---\n");
    RUN_TEST(test_initialization);
    RUN_TEST(test_config_loading_from_env);
    RUN_TEST(test_key_generation);
    RUN_TEST(test_argon2id_baseline_validation);
    RUN_TEST(test_key_derivation_determinism);
    RUN_TEST(test_encryption_decryption_roundtrip);
    RUN_TEST(test_decryption_failure_wrong_key);
    RUN_TEST(test_decryption_failure_tampered_ciphertext);
    printf("--- Test Suite Finished ---\n");
}

int main() {
    if (sodium_init() < 0) {
        printf("Fatal: Could not initialize libsodium for tests.\n");
        return 1;
    }

    run_all_tests();
    
    if (tests_failed > 0) {
        printf("\n\033[31mRESULT: %d assertion(s) FAILED across all tests.\033[0m\n", tests_failed);
        return 1;
    } else {
        printf("\n\033[32mRESULT: All %d test functions PASSED.\033[0m\n", tests_run);
        return 0;
    }
}