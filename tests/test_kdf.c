// tests/test_kdf.c

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "core_crypto/crypto_client.h"
#include "common/secure_memory.h"

// --- 测试辅助宏 ---
#define TEST_ASSERT(condition, message) do { \
    if (!(condition)) { \
        fprintf(stderr, "TEST FAILED: %s (%s:%d)\n", message, __FILE__, __LINE__); \
        return -1; \
    } \
} while(0)

// --- 测试用例 ---

/**
 * @brief 测试基本的密钥派生功能
 */
int test_kdf_basic_derivation() {
    printf("  Running test: test_kdf_basic_derivation...\n");
    const char* password = "correct horse battery staple";
    unsigned char salt[USER_SALT_BYTES];
    unsigned char pepper[32];
    unsigned char derived_key[SESSION_KEY_BYTES];

    randombytes_buf(salt, sizeof(salt));
    randombytes_buf(pepper, sizeof(pepper));

    int res = derive_key_from_password(
        derived_key, sizeof(derived_key),
        password, salt,
        g_argon2_opslimit, g_argon2_memlimit,
        pepper, sizeof(pepper)
    );
    
    TEST_ASSERT(res == 0, "KDF should succeed with valid parameters");

    printf("    ... PASSED\n");
    return 0;
}

/**
 * @brief 验证KDF的确定性：相同的输入必须产生相同的输出
 */
int test_kdf_deterministic() {
    printf("  Running test: test_kdf_deterministic...\n");
    const char* password = "a fixed and known password";
    unsigned char salt[USER_SALT_BYTES];
    unsigned char pepper[32];
    unsigned char dk1[SESSION_KEY_BYTES];
    unsigned char dk2[SESSION_KEY_BYTES];

    // 使用固定的 salt 和 pepper
    memset(salt, 0xAA, sizeof(salt));
    memset(pepper, 0xBB, sizeof(pepper));

    derive_key_from_password(dk1, sizeof(dk1), password, salt, g_argon2_opslimit, g_argon2_memlimit, pepper, sizeof(pepper));
    derive_key_from_password(dk2, sizeof(dk2), password, salt, g_argon2_opslimit, g_argon2_memlimit, pepper, sizeof(pepper));
    
    TEST_ASSERT(sodium_memcmp(dk1, dk2, sizeof(dk1)) == 0, "KDF must be deterministic");

    printf("    ... PASSED\n");
    return 0;
}

/**
 * @brief 验证KDF对每个输入的敏感性：任何输入的改变都应产生完全不同的输出
 */
int test_kdf_input_sensitivity() {
    printf("  Running test: test_kdf_input_sensitivity...\n");
    const char* password = "my_super_secret_password";
    const char* password2 = "my_super_secret_passw0rd"; // 略有不同

    unsigned char salt[USER_SALT_BYTES], salt2[USER_SALT_BYTES];
    unsigned char pepper[32], pepper2[32];
    unsigned char dk_base[SESSION_KEY_BYTES], dk_test[SESSION_KEY_BYTES];

    randombytes_buf(salt, sizeof(salt));
    memcpy(salt2, salt, sizeof(salt));
    salt2[0] ^= 0x01; // salt 略有不同

    randombytes_buf(pepper, sizeof(pepper));
    memcpy(pepper2, pepper, sizeof(pepper));
    pepper2[0] ^= 0x01; // pepper 略有不同

    // 1. 基准派生
    derive_key_from_password(dk_base, sizeof(dk_base), password, salt, g_argon2_opslimit, g_argon2_memlimit, pepper, sizeof(pepper));

    // 2. 测试不同密码
    derive_key_from_password(dk_test, sizeof(dk_test), password2, salt, g_argon2_opslimit, g_argon2_memlimit, pepper, sizeof(pepper));
    TEST_ASSERT(sodium_memcmp(dk_base, dk_test, sizeof(dk_base)) != 0, "Different passwords must produce different keys");

    // 3. 测试不同盐
    derive_key_from_password(dk_test, sizeof(dk_test), password, salt2, g_argon2_opslimit, g_argon2_memlimit, pepper, sizeof(pepper));
    TEST_ASSERT(sodium_memcmp(dk_base, dk_test, sizeof(dk_base)) != 0, "Different salts must produce different keys");

    // 4. 测试不同胡椒
    derive_key_from_password(dk_test, sizeof(dk_test), password, salt, g_argon2_opslimit, g_argon2_memlimit, pepper2, sizeof(pepper2));
    TEST_ASSERT(sodium_memcmp(dk_base, dk_test, sizeof(dk_base)) != 0, "Different peppers must produce different keys");
    
    printf("    ... PASSED\n");
    return 0;
}

/**
 * @brief 测试KDF是否会拒绝低于安全基线的参数
 */
int test_kdf_rejects_weak_params() {
    printf("  Running test: test_kdf_rejects_weak_params...\n");
    const char* password = "password123";
    unsigned char salt[USER_SALT_BYTES], pepper[32], derived_key[32];
    randombytes_buf(salt, sizeof(salt));
    randombytes_buf(pepper, sizeof(pepper));

    // 1. 测试过低的 opslimit
    int res_op = derive_key_from_password(derived_key, sizeof(derived_key), password, salt, 
                                          BASELINE_ARGON2ID_OPSLIMIT - 1, 
                                          g_argon2_memlimit, 
                                          pepper, sizeof(pepper));
    TEST_ASSERT(res_op == -1, "KDF must reject opslimit below baseline");

    // 2. 测试过低的 memlimit
    int res_mem = derive_key_from_password(derived_key, sizeof(derived_key), password, salt, 
                                          g_argon2_opslimit, 
                                          BASELINE_ARGON2ID_MEMLIMIT - 1, 
                                          pepper, sizeof(pepper));
    TEST_ASSERT(res_mem == -1, "KDF must reject memlimit below baseline");

    printf("    ... PASSED\n");
    return 0;
}

int main() {
    if (crypto_client_init() != 0) {
        fprintf(stderr, "Fatal: crypto_client_init failed\n");
        return 1;
    }

    printf("--- Running Key Derivation Function Test Suite ---\n");
    if (test_kdf_basic_derivation() != 0) return 1;
    if (test_kdf_deterministic() != 0) return 1;
    if (test_kdf_input_sensitivity() != 0) return 1;
    if (test_kdf_rejects_weak_params() != 0) return 1;

    printf("--- Key Derivation Function Test Suite: ALL PASSED ---\n\n");
    return 0;
}