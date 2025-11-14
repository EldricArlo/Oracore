// --- crypto_client.c (REVISED BY COMMITTEE FOR LOGGING CALLBACK) ---
#include "crypto_client.h"
#include "../common/secure_memory.h"
#include "../common/internal_logger.h"

#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h> // 包含 errno.h 以检查 strtoull 的范围错误

// --- 运行时安全参数的定义与初始化 ---
// 这些变量持有程序实际使用的Argon2id参数。
// 它们被初始化为编译时的基线值，确保在任何配置加载前都有一个安全的默认值。
unsigned long long g_argon2_opslimit = BASELINE_ARGON2ID_OPSLIMIT;
size_t g_argon2_memlimit = BASELINE_ARGON2ID_MEMLIMIT;


/**
 * @brief 从环境变量加载并验证密码学参数。
 *        此函数会读取 HSC_ARGON2_OPSLIMIT 和 HSC_ARGON2_MEMLIMIT 环境变量。
 *        如果环境变量被设置、解析成功，并且其值不低于内置的安全基线，
 *        则程序将使用这些更高强度的值。否则，将通过日志系统打印警告并保持安全的默认基线值。
 */
void crypto_config_load_from_env() {
    _hsc_log(HSC_LOG_LEVEL_INFO, "Loading cryptographic parameters...");

    // --- 加载 Ops Limit ---
    const char* opslimit_env = getenv("HSC_ARGON2_OPSLIMIT");
    if (opslimit_env) {
        char* endptr;
        errno = 0; // 在调用 strtoull 之前重置 errno
        unsigned long long ops_from_env = strtoull(opslimit_env, &endptr, 10);

        // 增强检查: 1. 转换是否溢出 2. 字符串是否完全转换 3. 值是否不低于基线
        if (errno == ERANGE) {
            _hsc_log(HSC_LOG_LEVEL_WARN, "  > WARNING: HSC_ARGON2_OPSLIMIT value is out of range. Using default.");
        } else if (*endptr == '\0' && ops_from_env >= BASELINE_ARGON2ID_OPSLIMIT) {
            g_argon2_opslimit = ops_from_env;
            _hsc_log(HSC_LOG_LEVEL_INFO, "  > Argon2id OpsLimit overridden by environment: %llu", g_argon2_opslimit);
        } else {
            _hsc_log(HSC_LOG_LEVEL_WARN, "  > WARNING: Invalid or below-baseline HSC_ARGON2_OPSLIMIT ignored. Using default.");
        }
    }

    // --- 加载 Mem Limit ---
    const char* memlimit_env = getenv("HSC_ARGON2_MEMLIMIT");
    if (memlimit_env) {
        char* endptr;
        errno = 0; // 在调用 strtoull 之前重置 errno
        unsigned long long mem_from_env = strtoull(memlimit_env, &endptr, 10);
        
        // 增强检查: 1. 转换是否溢出 2. 字符串是否完全转换 3. 值是否不低于基线
        if (errno == ERANGE) {
            _hsc_log(HSC_LOG_LEVEL_WARN, "  > WARNING: HSC_ARGON2_MEMLIMIT value is out of range. Using default.");
        } else if (*endptr == '\0' && mem_from_env >= BASELINE_ARGON2ID_MEMLIMIT) {
            g_argon2_memlimit = (size_t)mem_from_env;
            _hsc_log(HSC_LOG_LEVEL_INFO, "  > Argon2id MemLimit overridden by environment: %zu bytes", g_argon2_memlimit);
        } else {
            _hsc_log(HSC_LOG_LEVEL_WARN, "  > WARNING: Invalid or below-baseline HSC_ARGON2_MEMLIMIT ignored. Using default.");
        }
    }
    
    _hsc_log(HSC_LOG_LEVEL_INFO, "  > Final effective Argon2id parameters: OpsLimit=%llu, MemLimit=%zu MB",
           g_argon2_opslimit, g_argon2_memlimit / (1024 * 1024));
}

int crypto_client_init() {
    // 规范要求: 必须使用经过审查的专业密码学库。
    // sodium_init() 初始化 libsodium，并选择最优的、与平台无关的算法实现。
    // 它是线程安全的，可以多次调用。
    if (sodium_init() < 0) {
        return -1; // 初始化失败
    }

    // 初始化后立即从环境变量加载配置参数
    crypto_config_load_from_env();
    
    return 0;
}

/**
 * @brief 生成一个全新的 Ed25519 主密钥对，用于签名。
 */
int generate_master_key_pair(master_key_pair* kp) {
    if (kp == NULL) {
        return -1;
    }

    kp->sk = secure_alloc(MASTER_SECRET_KEY_BYTES);
    if (kp->sk == NULL) {
        return -1;
    }

    crypto_sign_keypair(kp->pk, kp->sk);

    return 0;
}

void free_master_key_pair(master_key_pair* kp) {
    if (kp != NULL && kp->sk != NULL) {
        secure_free(kp->sk);
        kp->sk = NULL;
    }
}

int generate_recovery_key(recovery_key* rk) {
    if (rk == NULL) {
        return -1;
    }
    rk->key = secure_alloc(RECOVERY_KEY_BYTES);
    if (rk->key == NULL) {
        return -1;
    }
    randombytes_buf(rk->key, RECOVERY_KEY_BYTES);
    return 0;
}

void free_recovery_key(recovery_key* rk) {
    if (rk != NULL && rk->key != NULL) {
        secure_free(rk->key);
        rk->key = NULL;
    }
}

bool validate_argon2id_params(unsigned long long opslimit, size_t memlimit) {
    if (opslimit < BASELINE_ARGON2ID_OPSLIMIT || memlimit < BASELINE_ARGON2ID_MEMLIMIT) {
        return false;
    }
    return true;
}

int derive_key_from_password(
    unsigned char* derived_key, size_t derived_key_len,
    const char* password,
    const unsigned char* salt,
    unsigned long long opslimit, size_t memlimit,
    const unsigned char* global_pepper, size_t pepper_len
) {
    if (derived_key == NULL || password == NULL || salt == NULL || global_pepper == NULL) {
        return -1;
    }

    int ret = -1;
    unsigned char* hashed_input = NULL;

    if (!validate_argon2id_params(opslimit, memlimit)) {
        goto cleanup;
    }
    
    hashed_input = secure_alloc(crypto_generichash_BYTES);
    if (!hashed_input) { goto cleanup; }

    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, crypto_generichash_BYTES);
    crypto_generichash_update(&state, global_pepper, pepper_len);
    crypto_generichash_update(&state, (const unsigned char*)password, strlen(password));
    crypto_generichash_final(&state, hashed_input, crypto_generichash_BYTES);

    if (crypto_pwhash(derived_key, derived_key_len,
                       (const char*)hashed_input, crypto_generichash_BYTES,
                       salt, opslimit, memlimit,
                       crypto_pwhash_ALG_DEFAULT) != 0) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (hashed_input) {
        secure_free(hashed_input);
        hashed_input = NULL;
    }

    return ret;
}

int encrypt_symmetric_aead(
    unsigned char* ciphertext, unsigned long long* ciphertext_len,
    const unsigned char* message, size_t message_len,
    const unsigned char* key
) {
    if (ciphertext == NULL || ciphertext_len == NULL || message == NULL || key == NULL) {
        return -1;
    }
    
    const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    unsigned char* nonce = ciphertext;
    unsigned char* actual_ciphertext = ciphertext + nonce_len;
    
    randombytes_buf(nonce, nonce_len);
    
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            actual_ciphertext, ciphertext_len,
            message, message_len,
            NULL, 0,
            NULL,
            nonce,
            key
        ) != 0) {
        return -1;
    }

    *ciphertext_len += nonce_len;
    
    return 0;
}

int decrypt_symmetric_aead(
    unsigned char* decrypted_message, unsigned long long* decrypted_message_len,
    const unsigned char* ciphertext, size_t ciphertext_len,
    const unsigned char* key
) {
    if (decrypted_message == NULL || decrypted_message_len == NULL || ciphertext == NULL || key == NULL) {
        return -1;
    }

    const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    if (ciphertext_len < nonce_len) {
        return -1;
    }

    const unsigned char* nonce = ciphertext;
    const unsigned char* actual_ciphertext = ciphertext + nonce_len;
    const size_t actual_ciphertext_len = ciphertext_len - nonce_len;
    
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
        decrypted_message, decrypted_message_len,
        NULL,
        actual_ciphertext, actual_ciphertext_len,
        NULL, 0,
        nonce,
        key
    ) != 0) {
        return -1;
    }

    return 0;
}

// --- 分离模式 AEAD 实现 ---

int encrypt_symmetric_aead_detached(unsigned char* ciphertext, unsigned char* tag_out,
                                    const unsigned char* message, size_t message_len,
                                    const unsigned char* additional_data, size_t ad_len,
                                    const unsigned char* nonce, const unsigned char* key) {
    if (ciphertext == NULL || tag_out == NULL || message == NULL || nonce == NULL || key == NULL) {
        return -1;
    }
    
    unsigned long long ciphertext_len_out;
    
    if (crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            ciphertext,
            tag_out,
            &ciphertext_len_out,
            message, message_len,
            additional_data, ad_len,
            NULL,
            nonce,
            key
        ) != 0) {
        return -1;
    }

    return 0;
}

int decrypt_symmetric_aead_detached(unsigned char* decrypted_message,
                                    const unsigned char* ciphertext, size_t ciphertext_len,
                                    const unsigned char* tag,
                                    const unsigned char* additional_data, size_t ad_len,
                                    const unsigned char* nonce, const unsigned char* key) {
    if (decrypted_message == NULL || ciphertext == NULL || tag == NULL || nonce == NULL || key == NULL) {
        return -1;
    }
    
    if (crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            decrypted_message,
            NULL,
            ciphertext, ciphertext_len,
            tag,
            additional_data, ad_len,
            nonce,
            key
        ) != 0) {
        return -1;
    }

    return 0;
}

int encapsulate_session_key(unsigned char* encrypted_output,
                            size_t* encrypted_output_len,
                            const unsigned char* session_key, size_t session_key_len,
                            const unsigned char* recipient_sign_pk,
                            const unsigned char* my_sign_sk) {
    
    if (encrypted_output == NULL || encrypted_output_len == NULL || session_key == NULL || recipient_sign_pk == NULL || my_sign_sk == NULL) {
        return -1;
    }

    unsigned char recipient_encrypt_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char* my_encrypt_sk = secure_alloc(crypto_box_SECRETKEYBYTES);
    if (my_encrypt_sk == NULL) {
        return -1;
    }

    if (crypto_sign_ed25519_pk_to_curve25519(recipient_encrypt_pk, recipient_sign_pk) != 0) {
        secure_free(my_encrypt_sk);
        return -1;
    }
    if (crypto_sign_ed25519_sk_to_curve25519(my_encrypt_sk, my_sign_sk) != 0) {
        secure_free(my_encrypt_sk);
        return -1;
    }
    
    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    unsigned char* ciphertext_ptr = encrypted_output + crypto_box_NONCEBYTES;
    
    int result = crypto_box_easy(ciphertext_ptr, session_key, session_key_len,
                                 nonce,
                                 recipient_encrypt_pk, my_encrypt_sk);
    
    if (result == 0) {
        memcpy(encrypted_output, nonce, sizeof(nonce));
        *encrypted_output_len = crypto_box_NONCEBYTES + session_key_len + crypto_box_MACBYTES;
    } else {
        *encrypted_output_len = 0;
    }

    secure_free(my_encrypt_sk);
    
    return result;
}

int decapsulate_session_key(unsigned char* decrypted_output,
                            const unsigned char* encrypted_input, size_t encrypted_input_len,
                            const unsigned char* sender_sign_pk,
                            const unsigned char* my_sign_sk) {

    if (decrypted_output == NULL || encrypted_input == NULL || sender_sign_pk == NULL || my_sign_sk == NULL) {
        return -1;
    }

    if (encrypted_input_len < crypto_box_NONCEBYTES) {
        return -1;
    }
    
    const unsigned char* nonce = encrypted_input;
    const unsigned char* actual_ciphertext = encrypted_input + crypto_box_NONCEBYTES;
    const size_t actual_ciphertext_len = encrypted_input_len - crypto_box_NONCEBYTES;

    unsigned char sender_encrypt_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char* my_encrypt_sk = secure_alloc(crypto_box_SECRETKEYBYTES);
    if (my_encrypt_sk == NULL) {
        return -1;
    }

    if (crypto_sign_ed25519_pk_to_curve25519(sender_encrypt_pk, sender_sign_pk) != 0) {
        secure_free(my_encrypt_sk);
        return -1;
    }
    if (crypto_sign_ed25519_sk_to_curve25519(my_encrypt_sk, my_sign_sk) != 0) {
        secure_free(my_encrypt_sk);
        return -1;
    }

    int result = crypto_box_open_easy(decrypted_output, actual_ciphertext, actual_ciphertext_len,
                                      nonce,
                                      sender_encrypt_pk, my_encrypt_sk);

    secure_free(my_encrypt_sk);

    return result;
}