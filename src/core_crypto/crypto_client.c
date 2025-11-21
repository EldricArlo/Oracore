#include "crypto_client.h"
#include "../common/secure_memory.h"
#include "../common/internal_logger.h"

#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h> 

// --- 运行时安全参数的定义与初始化 ---
unsigned long long g_argon2_opslimit = BASELINE_ARGON2ID_OPSLIMIT;
size_t g_argon2_memlimit = BASELINE_ARGON2ID_MEMLIMIT;

// 全局胡椒现在存储在安全内存中，并在运行时加载
static unsigned char* g_internal_pepper = NULL;
static size_t g_internal_pepper_len = 0;
#define REQUIRED_PEPPER_BYTES 32


/**
 * @brief [内部] 将十六进制字符转换为其整数值。
 */
static int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * @brief [内部] 加载并验证全局胡椒。
 *        [FIX]: 支持显式传入或从环境变量回退。
 */
static int _load_pepper(const char* explicit_hex) {
    _hsc_log(HSC_LOG_LEVEL_INFO, "Loading global cryptographic pepper...");

    const char* pepper_hex = NULL;
    bool is_from_env = false;

    if (explicit_hex != NULL) {
        pepper_hex = explicit_hex;
        _hsc_log(HSC_LOG_LEVEL_INFO, "  > Using explicitly provided pepper.");
    } else {
        pepper_hex = getenv("HSC_PEPPER_HEX");
        if (pepper_hex == NULL) {
            _hsc_log(HSC_LOG_LEVEL_ERROR, "  > FATAL: Security pepper not provided via arguments and 'HSC_PEPPER_HEX' environment variable is not set.");
            return -1;
        }
        is_from_env = true;
        _hsc_log(HSC_LOG_LEVEL_INFO, "  > Using pepper from environment variable 'HSC_PEPPER_HEX'.");
    }

    size_t hex_len = strlen(pepper_hex);
    if (hex_len != REQUIRED_PEPPER_BYTES * 2) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "  > FATAL: Pepper must be exactly %zu hex characters long, but got %zu.", REQUIRED_PEPPER_BYTES * 2, hex_len);
        // [FIX]: Finding #1 - 不再尝试擦除环境变量，因为可能导致段错误。
        // 如果长度错误，直接返回错误即可。
        return -1;
    }

    g_internal_pepper = secure_alloc(REQUIRED_PEPPER_BYTES);
    if (g_internal_pepper == NULL) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "  > FATAL: Failed to allocate secure memory for the pepper.");
        return -1;
    }
    
    for (size_t i = 0; i < REQUIRED_PEPPER_BYTES; ++i) {
        int high = hex_char_to_int(pepper_hex[2 * i]);
        int low = hex_char_to_int(pepper_hex[2 * i + 1]);
        if (high == -1 || low == -1) {
            secure_free(g_internal_pepper);
            g_internal_pepper = NULL;
            _hsc_log(HSC_LOG_LEVEL_ERROR, "  > FATAL: Pepper contains invalid non-hexadecimal characters.");
            // [FIX]: Finding #1 - 同样，不再尝试擦除环境变量。
            return -1;
        }
        g_internal_pepper[i] = (unsigned char)((high << 4) | low);
    }

    g_internal_pepper_len = REQUIRED_PEPPER_BYTES;
    _hsc_log(HSC_LOG_LEVEL_INFO, "  > Successfully loaded and validated the %zu-byte global pepper.", g_internal_pepper_len);

    // [FIX]: Finding #1 Remediation
    // 移除了对 getenv 返回指针的 sodium_memzero 调用。
    // 修改环境变量内存属于未定义行为，可能导致程序崩溃 (Crash)。
    // 安全性依赖于操作系统的进程隔离。
    if (is_from_env) {
        _hsc_log(HSC_LOG_LEVEL_WARN, "  > [SECURITY] Note: Sensitive pepper loaded from environment. Ensure process environment is isolated.");
    }
    
    return 0;
}


void crypto_config_load_from_env() {
    _hsc_log(HSC_LOG_LEVEL_INFO, "Loading cryptographic parameters...");

    // --- 加载 Ops Limit ---
    const char* opslimit_env = getenv("HSC_ARGON2_OPSLIMIT");
    if (opslimit_env) {
        char* endptr;
        errno = 0;
        unsigned long long ops_from_env = strtoull(opslimit_env, &endptr, 10);
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
        errno = 0;
        unsigned long long mem_from_env = strtoull(memlimit_env, &endptr, 10);
        if (errno == ERANGE) {
            _hsc_log(HSC_LOG_LEVEL_WARN, "  > WARNING: HSC_ARGON2_MEMLIMIT value is out of range. Using default.");
        } else if (*endptr == '\0' && mem_from_env >= BASELINE_ARGON2ID_MEMLIMIT) {
            g_argon2_memlimit = (size_t)mem_from_env;
            _hsc_log(HSC_LOG_LEVEL_INFO, "  > Argon2id MemLimit overridden by environment: %zu bytes", g_argon2_memlimit);
        } else {
            _hsc_log(HSC_LOG_LEVEL_WARN, "  > WARNING: Invalid or below-baseline HSC_ARGON2_MEMLIMIT ignored. Using default.");
        }
    }
}

// [FIX]: 更新签名以接收显式 Pepper
int crypto_client_init(const char* explicit_pepper_hex) {
    if (sodium_init() < 0) return -1;
    if (_load_pepper(explicit_pepper_hex) != 0) return -1;
    crypto_config_load_from_env();
    return 0;
}

void crypto_client_cleanup() {
    if (g_internal_pepper) {
        secure_free(g_internal_pepper);
        g_internal_pepper = NULL;
        g_internal_pepper_len = 0;
    }
}

const unsigned char* get_global_pepper(size_t* out_len) {
    if (out_len) *out_len = g_internal_pepper_len;
    return g_internal_pepper;
}

// [修复] 重构：分别分配和生成身份密钥与加密密钥
int generate_master_key_pair(master_key_pair* kp) {
    if (kp == NULL) return -1;
    
    // 1. 初始化指针为 NULL，方便 cleanup 处理
    kp->identity_sk = NULL;
    kp->encryption_sk = NULL;

    // 2. 分配身份私钥内存
    kp->identity_sk = secure_alloc(crypto_sign_SECRETKEYBYTES);
    if (kp->identity_sk == NULL) goto cleanup;

    // 3. 分配加密私钥内存
    kp->encryption_sk = secure_alloc(crypto_box_SECRETKEYBYTES);
    if (kp->encryption_sk == NULL) goto cleanup;

    // 4. 生成 Ed25519 身份密钥对
    if (crypto_sign_keypair(kp->identity_pk, kp->identity_sk) != 0) {
        goto cleanup;
    }

    // 5. [关键修复] 立即派生并隔离加密密钥
    // 虽然这里仍是数学转换，但我们将转换后的结果存储在独立的 encryption_* 字段中。
    // 之后的加密操作将只引用 encryption_sk，不再接触 identity_sk。
    
    // 5a. 转换公钥: Ed25519 PK -> X25519 PK
    if (crypto_sign_ed25519_pk_to_curve25519(kp->encryption_pk, kp->identity_pk) != 0) {
        goto cleanup;
    }

    // 5b. 转换私钥: Ed25519 SK -> X25519 SK
    if (crypto_sign_ed25519_sk_to_curve25519(kp->encryption_sk, kp->identity_sk) != 0) {
        goto cleanup;
    }

    return 0;

cleanup:
    // 如果任何一步失败，释放所有已分配的内存
    if (kp->identity_sk) secure_free(kp->identity_sk);
    if (kp->encryption_sk) secure_free(kp->encryption_sk);
    kp->identity_sk = NULL;
    kp->encryption_sk = NULL;
    return -1;
}

// [修复] 重构：分别释放两个私钥
void free_master_key_pair(master_key_pair* kp) {
    if (kp != NULL) {
        if (kp->identity_sk != NULL) {
            secure_free(kp->identity_sk);
            kp->identity_sk = NULL;
        }
        if (kp->encryption_sk != NULL) {
            secure_free(kp->encryption_sk);
            kp->encryption_sk = NULL;
        }
    }
}

int generate_recovery_key(recovery_key* rk) {
    if (rk == NULL) return -1;
    rk->key = secure_alloc(RECOVERY_KEY_BYTES);
    if (rk->key == NULL) return -1;
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
    if (derived_key == NULL || password == NULL || salt == NULL || global_pepper == NULL) return -1;
    if (pepper_len == 0) return -1;

    int ret = -1;
    unsigned char* hashed_input = NULL;

    if (!validate_argon2id_params(opslimit, memlimit)) goto cleanup;
    
    hashed_input = secure_alloc(crypto_generichash_BYTES);
    if (!hashed_input) goto cleanup;

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
    if (hashed_input) secure_free(hashed_input);
    return ret;
}

int encrypt_symmetric_aead(
    unsigned char* ciphertext, unsigned long long* ciphertext_len,
    const unsigned char* message, size_t message_len,
    const unsigned char* key
) {
    if (ciphertext == NULL || ciphertext_len == NULL || message == NULL || key == NULL) return -1;
    
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
    if (decrypted_message == NULL || decrypted_message_len == NULL || ciphertext == NULL || key == NULL) return -1;

    const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    if (ciphertext_len < nonce_len) return -1;

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

int encrypt_symmetric_aead_detached(unsigned char* ciphertext, unsigned char* tag_out,
                                    const unsigned char* message, size_t message_len,
                                    const unsigned char* additional_data, size_t ad_len,
                                    const unsigned char* nonce, const unsigned char* key) {
    if (ciphertext == NULL || tag_out == NULL || message == NULL || nonce == NULL || key == NULL) return -1;
    
    unsigned long long ciphertext_len_out;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            ciphertext, tag_out, &ciphertext_len_out,
            message, message_len, additional_data, ad_len, NULL, nonce, key
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
    if (decrypted_message == NULL || ciphertext == NULL || tag == NULL || nonce == NULL || key == NULL) return -1;
    
    if (crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            decrypted_message, NULL,
            ciphertext, ciphertext_len,
            tag, additional_data, ad_len, nonce, key
        ) != 0) {
        return -1;
    }
    return 0;
}

// [修复] 重构：使用传入的 dedicated encryption key，不再进行临时转换
int encapsulate_session_key(unsigned char* encrypted_output,
                            size_t* encrypted_output_len,
                            const unsigned char* session_key, size_t session_key_len,
                            const unsigned char* recipient_sign_pk,
                            const unsigned char* my_enc_sk) {
    
    if (encrypted_output == NULL || encrypted_output_len == NULL || session_key == NULL || recipient_sign_pk == NULL || my_enc_sk == NULL) {
        return -1;
    }

    // 1. 转换接收者的公钥 (Ed25519 PK -> X25519 PK)
    //    这是必要的，因为我们通常只知道接收者的身份公钥（例如来自证书）。
    //    这个操作是公钥到公钥的转换，不涉及私钥，是安全的。
    unsigned char recipient_encrypt_pk[crypto_box_PUBLICKEYBYTES];
    if (crypto_sign_ed25519_pk_to_curve25519(recipient_encrypt_pk, recipient_sign_pk) != 0) {
        return -1;
    }

    // 2. [关键变更] 不再在这里将 my_sign_sk 转换为临时私钥。
    //    直接使用传入的 my_enc_sk (X25519 key)。
    
    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    unsigned char* ciphertext_ptr = encrypted_output + crypto_box_NONCEBYTES;
    
    // 3. 使用 Box 算法进行非对称加密
    int result = crypto_box_easy(ciphertext_ptr, session_key, session_key_len,
                                 nonce,
                                 recipient_encrypt_pk, my_enc_sk);
    
    if (result == 0) {
        memcpy(encrypted_output, nonce, sizeof(nonce));
        *encrypted_output_len = crypto_box_NONCEBYTES + session_key_len + crypto_box_MACBYTES;
    } else {
        *encrypted_output_len = 0;
    }
    
    return result;
}

// [修复] 重构：使用传入的 dedicated encryption key，不再进行临时转换
int decapsulate_session_key(unsigned char* decrypted_output,
                            const unsigned char* encrypted_input, size_t encrypted_input_len,
                            const unsigned char* sender_sign_pk,
                            const unsigned char* my_enc_sk) {

    if (decrypted_output == NULL || encrypted_input == NULL || sender_sign_pk == NULL || my_enc_sk == NULL) {
        return -1;
    }

    if (encrypted_input_len < crypto_box_NONCEBYTES) {
        return -1;
    }
    
    const unsigned char* nonce = encrypted_input;
    const unsigned char* actual_ciphertext = encrypted_input + crypto_box_NONCEBYTES;
    const size_t actual_ciphertext_len = encrypted_input_len - crypto_box_NONCEBYTES;

    // 1. 转换发送者的公钥 (Ed25519 PK -> X25519 PK)
    //    我们需要知道是谁发的（从证书提取的Sign PK），然后转换成Encrypt PK来验证和解密。
    unsigned char sender_encrypt_pk[crypto_box_PUBLICKEYBYTES];
    if (crypto_sign_ed25519_pk_to_curve25519(sender_encrypt_pk, sender_sign_pk) != 0) {
        return -1;
    }

    // 2. [关键变更] 直接使用 my_enc_sk 进行解密
    int result = crypto_box_open_easy(decrypted_output, actual_ciphertext, actual_ciphertext_len,
                                      nonce,
                                      sender_encrypt_pk, my_enc_sk);

    return result;
}