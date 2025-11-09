#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "core_crypto/crypto_client.h"
#include "pki/pki_handler.h"
#include "test_helpers.h" // 包含新的共享测试辅助函数头文件

/**
 * @brief 测试 CSR 的生成与释放流程
 */
static int test_csr_generation() {
    printf("  Running test: test_csr_generation...\n");
    int ret = -1;
    master_key_pair mkp = { .sk = NULL };
    char* csr_pem = NULL;

    if (generate_master_key_pair(&mkp) != 0) goto cleanup;
    if (generate_csr(&mkp, "csr.user@test.com", &csr_pem) != 0) goto cleanup;
    if (csr_pem == NULL) goto cleanup;
    
    ret = 0;
    printf("    ... PASSED\n");

cleanup:
    free_master_key_pair(&mkp);
    free_csr_pem(csr_pem);
    return ret;
}

/**
 * @brief 测试从有效证书中提取公钥
 */
static int test_public_key_extraction() {
    printf("  Running test: test_public_key_extraction...\n");
    int ret = -1;
    master_key_pair mkp = { .sk = NULL };
    char* csr_pem = NULL, *ca_key = NULL, *ca_cert = NULL, *user_cert = NULL;
    unsigned char extracted_pk[MASTER_PUBLIC_KEY_BYTES];

    if (generate_master_key_pair(&mkp) != 0) goto cleanup;
    if (generate_csr(&mkp, "pk.user@test.com", &csr_pem) != 0) goto cleanup;
    if (generate_test_ca(&ca_key, &ca_cert, 0xAA) != 0) goto cleanup;
    // [核心修改] 调用共享的辅助函数
    if (sign_csr_with_ca(&user_cert, csr_pem, ca_key, ca_cert, 0, 31536000L) != 0) goto cleanup;

    if (extract_public_key_from_cert(user_cert, extracted_pk) != 0) goto cleanup;
    if (sodium_memcmp(mkp.pk, extracted_pk, MASTER_PUBLIC_KEY_BYTES) != 0) goto cleanup;

    ret = 0;
    printf("    ... PASSED\n");
    
cleanup:
    free_master_key_pair(&mkp);
    free_csr_pem(csr_pem);
    free(ca_key);
    free(ca_cert);
    free(user_cert);
    return ret;
}

/**
 * @brief 测试证书验证的“成功”路径。
 *        注意：由于测试证书指向一个无效的OCSP服务器，预期结果是OCSP检查失败（-4）。
 *        这验证了我们的“故障关闭”策略。
 */
static int test_verification_successful_path() {
    printf("  Running test: test_verification_successful_path...\n");
    int ret = -1;
    master_key_pair user_kp = { .sk = NULL };
    char* ca_key = NULL, *ca_cert = NULL, *user_csr = NULL, *user_cert = NULL;
    const char* username = "valid.user@test.com";

    if (generate_test_ca(&ca_key, &ca_cert, 0xBB) != 0) goto cleanup;
    if (generate_master_key_pair(&user_kp) != 0) goto cleanup;
    if (generate_csr(&user_kp, username, &user_csr) != 0) goto cleanup;
    // [核心修改] 调用共享的辅助函数
    if (sign_csr_with_ca(&user_cert, user_csr, ca_key, ca_cert, 0, 31536000L) != 0) goto cleanup;

    int res = verify_user_certificate(user_cert, ca_cert, username);
    if (res != -4) {
        fprintf(stderr, "    > FAILED: Verification must fail with OCSP error (-4), but got %d\n", res);
        goto cleanup;
    }
    
    ret = 0;
    printf("    ... PASSED (OCSP check failed as expected)\n");

cleanup:
    free_master_key_pair(&user_kp);
    free_csr_pem(user_csr);
    free(ca_key); 
    free(ca_cert); 
    free(user_cert);
    return ret;
}

/**
 * @brief 测试使用不受信任的 CA 签发的证书，预期验证失败 (返回 -2)
 */
static int test_verification_untrusted_ca() {
    printf("  Running test: test_verification_untrusted_ca...\n");
    int ret = -1;
    master_key_pair user_kp = { .sk = NULL };
    char* trusted_ca_key = NULL, *trusted_ca_cert = NULL;
    char* untrusted_ca_key = NULL, *untrusted_ca_cert = NULL;
    char* user_csr = NULL, *user_cert = NULL;

    // 生成两个不同的 CA
    if (generate_test_ca(&trusted_ca_key, &trusted_ca_cert, 0xCC) != 0) goto cleanup; 
    if (generate_test_ca(&untrusted_ca_key, &untrusted_ca_cert, 0xDD) != 0) goto cleanup;
    
    if (generate_master_key_pair(&user_kp) != 0) goto cleanup;
    if (generate_csr(&user_kp, "user.untrusted@test.com", &user_csr) != 0) goto cleanup;
    
    // 使用“不受信任”的 CA 签署证书
    // [核心修改] 调用共享的辅助函数
    if (sign_csr_with_ca(&user_cert, user_csr, untrusted_ca_key, untrusted_ca_cert, 0, 31536000L) != 0) goto cleanup;

    // 使用“受信任”的 CA 进行验证，预期失败
    int res = verify_user_certificate(user_cert, trusted_ca_cert, "user.untrusted@test.com");
    if (res != -2) {
        fprintf(stderr, "    > FAILED: Verification with untrusted CA must fail with error (-2), but got %d\n", res);
        goto cleanup;
    }
    
    ret = 0;
    printf("    ... PASSED\n");

cleanup:
    free_master_key_pair(&user_kp);
    free_csr_pem(user_csr);
    free(trusted_ca_key); free(trusted_ca_cert);
    free(untrusted_ca_key); free(untrusted_ca_cert);
    free(user_cert);
    return ret;
}

/**
 * @brief 测试证书主题与预期用户名不匹配，预期验证失败 (返回 -3)
 */
static int test_verification_subject_mismatch() {
    printf("  Running test: test_verification_subject_mismatch...\n");
    int ret = -1;
    master_key_pair user_kp = { .sk = NULL };
    char* ca_key = NULL, *ca_cert = NULL, *user_csr = NULL, *user_cert = NULL;
    const char* actual_username = "alice@test.com";
    const char* expected_username = "bob@test.com";

    if (generate_test_ca(&ca_key, &ca_cert, 0xEE) != 0) goto cleanup;
    if (generate_master_key_pair(&user_kp) != 0) goto cleanup;
    if (generate_csr(&user_kp, actual_username, &user_csr) != 0) goto cleanup;
    // [核心修改] 调用共享的辅助函数
    if (sign_csr_with_ca(&user_cert, user_csr, ca_key, ca_cert, 0, 31536000L) != 0) goto cleanup;

    int res = verify_user_certificate(user_cert, ca_cert, expected_username);
    if (res != -3) {
        fprintf(stderr, "    > FAILED: Verification with wrong subject must fail with error (-3), but got %d\n", res);
        goto cleanup;
    }
    
    ret = 0;
    printf("    ... PASSED\n");

cleanup:
    free_master_key_pair(&user_kp);
    free_csr_pem(user_csr);
    free(ca_key); free(ca_cert); free(user_cert);
    return ret;
}

/**
 * @brief 测试已过期的证书，预期验证失败 (返回 -2)
 */
static int test_verification_expired_cert() {
    printf("  Running test: test_verification_expired_cert...\n");
    int ret = -1;
    master_key_pair user_kp = { .sk = NULL };
    char* ca_key = NULL, *ca_cert = NULL, *user_csr = NULL, *user_cert = NULL;
    const char* username = "expired.user@test.com";

    if (generate_test_ca(&ca_key, &ca_cert, 0xFF) != 0) goto cleanup;
    if (generate_master_key_pair(&user_kp) != 0) goto cleanup;
    if (generate_csr(&user_kp, username, &user_csr) != 0) goto cleanup;
    
    // 签发一个在2秒前生效，1秒前就已过期的证书
    // [核心修改] 调用共享的辅助函数
    if (sign_csr_with_ca(&user_cert, user_csr, ca_key, ca_cert, -2, -1) != 0) goto cleanup;

    int res = verify_user_certificate(user_cert, ca_cert, username);
    if (res != -2) {
        fprintf(stderr, "    > FAILED: Verification of expired cert must fail with error (-2), but got %d\n", res);
        goto cleanup;
    }

    ret = 0;
    printf("    ... PASSED\n");

cleanup:
    free_master_key_pair(&user_kp);
    free_csr_pem(user_csr);
    free(ca_key); free(ca_cert); free(user_cert);
    return ret;
}

/**
 * @brief 测试尚未生效的证书，预期验证失败 (返回 -2)
 */
static int test_verification_not_yet_valid_cert() {
    printf("  Running test: test_verification_not_yet_valid_cert...\n");
    int ret = -1;
    master_key_pair user_kp = { .sk = NULL };
    char* ca_key = NULL, *ca_cert = NULL, *user_csr = NULL, *user_cert = NULL;
    const char* username = "future.user@test.com";

    if (generate_test_ca(&ca_key, &ca_cert, 0x11) != 0) goto cleanup;
    if (generate_master_key_pair(&user_kp) != 0) goto cleanup;
    if (generate_csr(&user_kp, username, &user_csr) != 0) goto cleanup;
    
    // 签发一个1小时后才生效的证书
    // [核心修改] 调用共享的辅助函数
    if (sign_csr_with_ca(&user_cert, user_csr, ca_key, ca_cert, 3600, 3600 + 31536000L) != 0) goto cleanup;

    int res = verify_user_certificate(user_cert, ca_cert, username);
    if (res != -2) {
        fprintf(stderr, "    > FAILED: Verification of not-yet-valid cert must fail with error (-2), but got %d\n", res);
        goto cleanup;
    }
    
    ret = 0;
    printf("    ... PASSED\n");

cleanup:
    free_master_key_pair(&user_kp);
    free_csr_pem(user_csr);
    free(ca_key); free(ca_cert); free(user_cert);
    return ret;
}


int main() {
    if (crypto_client_init() != 0 || pki_init() != 0) {
        fprintf(stderr, "Fatal: Library initialization failed\n");
        return 1;
    }

    printf("\n--- Running Consolidated PKI Test Suite ---\n");
    
    if (test_csr_generation() != 0) return 1;
    if (test_public_key_extraction() != 0) return 1;
    if (test_verification_successful_path() != 0) return 1;
    if (test_verification_untrusted_ca() != 0) return 1;
    if (test_verification_subject_mismatch() != 0) return 1;
    if (test_verification_expired_cert() != 0) return 1;
    if (test_verification_not_yet_valid_cert() != 0) return 1;
    
    printf("\n\033[32m--- Consolidated PKI Test Suite: ALL PASSED ---\033[0m\n\n");
    return 0;
}

// 移除了此文件中所有的辅助函数实现（generate_test_ca 和 sign_csr_with_ca_timed）。
// 这些函数现在位于 tests/test_helpers.c 中。