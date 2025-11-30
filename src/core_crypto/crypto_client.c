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
 * 
 * [FIX]: 修复发现 #2 - 增加环境变量清理逻辑
 * 安全增强: 读取环境变量后，立即在内存中擦除其内容并从环境中移除，
 * 防止其他进程或后续的内存转储获取到明文 Pepper。
 */
static int _load_pepper(const char* explicit_hex) {
    _hsc_log(HSC_LOG_LEVEL_INFO, "Loading global cryptographic pepper...");

    const char* pepper_hex_source = NULL;
    char* env_ptr = NULL; // [FIX]: 用于持有非 const 的 getenv 返回指针
    bool is_from_env = false;

    if (explicit_hex != NULL) {
        pepper_hex_source = explicit_hex;
        _hsc_log(HSC_LOG_LEVEL_INFO, "  > Using explicitly provided pepper.");
    } else {
        env_ptr = getenv("HSC_PEPPER_HEX");
        if (env_ptr == NULL) {
            _hsc_log(HSC_LOG_LEVEL_ERROR, "  > FATAL: Security pepper not provided via arguments and 'HSC_PEPPER_HEX' environment variable is not set.");
            return -1;
        }
        pepper_hex_source = env_ptr;
        is_from_env = true;
        _hsc_log(HSC_LOG_LEVEL_INFO, "  > Using pepper from environment variable 'HSC_PEPPER_HEX'.");
    }

    size_t hex_len = strlen(pepper_hex_source);
    if (hex_len != REQUIRED_PEPPER_BYTES * 2) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "  > FATAL: Pepper must be exactly %zu hex characters long, but got %zu.", REQUIRED_PEPPER_BYTES * 2, hex_len);
        // [FIX]: 即使失败也要清理环境变量
        if (is_from_env && env_ptr) {
            sodium_memzero(env_ptr, hex_len);
        }
        return -1;
    }

    g_internal_pepper = secure_alloc(REQUIRED_PEPPER_BYTES);
    if (g_internal_pepper == NULL) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "  > FATAL: Failed to allocate secure memory for the pepper.");
         // [FIX]: 即使失败也要清理环境变量
        if (is_from_env && env_ptr) {
            sodium_memzero(env_ptr, hex_len);
        }
        return -1;
    }
    
    for (size_t i = 0; i < REQUIRED_PEPPER_BYTES; ++i) {
        int high = hex_char_to_int(pepper_hex_source[2 * i]);
        int low = hex_char_to_int(pepper_hex_source[2 * i + 1]);
        
        if (high == -1 || low == -1) {
            secure_free(g_internal_pepper);
            g_internal_pepper = NULL;
            _hsc_log(HSC_LOG_LEVEL_ERROR, "  > FATAL: Pepper contains invalid non-hexadecimal characters.");
            // [FIX]: 即使失败也要清理环境变量
            if (is_from_env && env_ptr) {
                sodium_memzero(env_ptr, hex_len);
            }
            return -1;
        }
        
        g_internal_pepper[i] = (unsigned char)((high << 4) | low);
    }

    g_internal_pepper_len = REQUIRED_PEPPER_BYTES;
    _hsc_log(HSC_LOG_LEVEL_INFO, "  > Successfully loaded and validated the %zu-byte global pepper.", g_internal_pepper_len);

    if (is_from_env) {
        _hsc_log(HSC_LOG_LEVEL_WARN, "  > [SECURITY] Note: Sensitive pepper loaded from environment. Performing memory scrub...");
        
        // [FIX]: 立即擦除环境变量所在的内存区域
        // 注意：这修改了 getenv 返回的内存，虽然在标准中行为未定义，
        // 但在 POSIX/Windows 实践中通常能有效擦除进程环境块中的数据。
        if (env_ptr) {
            sodium_memzero(env_ptr, hex_len);
        }

        // [FIX]: 从环境表中移除变量
        #ifdef _WIN32
            _putenv_s("HSC_PEPPER_HEX", "");
        #else
            unsetenv("HSC_PEPPER_HEX");
        #endif
        
        _hsc_log(HSC_LOG_LEVEL_INFO, "  > [SECURITY] Environment variable 'HSC_PEPPER_HEX' scrubbed and unset.");
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

int generate_master_key_pair(master_key_pair* kp) {
    if (kp == NULL) return -1;
    
    kp->identity_sk = NULL;
    kp->encryption_sk = NULL;

    // 分配身份私钥内存
    kp->identity_sk = secure_alloc(crypto_sign_SECRETKEYBYTES);
    if (kp->identity_sk == NULL) goto cleanup;

    // 分配加密私钥内存
    kp->encryption_sk = secure_alloc(crypto_box_SECRETKEYBYTES);
    if (kp->encryption_sk == NULL) goto cleanup;

    // 生成 Ed25519 身份密钥对
    if (crypto_sign_keypair(kp->identity_pk, kp->identity_sk) != 0) {
        goto cleanup;
    }

    // 派生并隔离加密密钥 (Ed25519 -> X25519)
    if (crypto_sign_ed25519_pk_to_curve25519(kp->encryption_pk, kp->identity_pk) != 0) {
        goto cleanup;
    }

    if (crypto_sign_ed25519_sk_to_curve25519(kp->encryption_sk, kp->identity_sk) != 0) {
        goto cleanup;
    }

    return 0;

cleanup:
    if (kp->identity_sk) secure_free(kp->identity_sk);
    if (kp->encryption_sk) secure_free(kp->encryption_sk);
    kp->identity_sk = NULL;
    kp->encryption_sk = NULL;
    return -1;
}

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
    unsigned char* ciphertext, size_t ciphertext_max_len,
    unsigned long long* ciphertext_len,
    const unsigned char* message, size_t message_len,
    const unsigned char* key
) {
    if (ciphertext == NULL || ciphertext_len == NULL || message == NULL || key == NULL) return -1;
    
    const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const size_t mac_len = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    size_t required_len = message_len + nonce_len + mac_len;

    // [FIX]: Output buffer boundary check
    if (ciphertext_max_len < required_len) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "AEAD Encrypt: Output buffer too small. Required: %zu, Provided: %zu", required_len, ciphertext_max_len);
        return -1;
    }

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
    unsigned char* decrypted_message, size_t decrypted_message_max_len,
    unsigned long long* decrypted_message_len,
    const unsigned char* ciphertext, size_t ciphertext_len,
    const unsigned char* key
) {
    if (decrypted_message == NULL || decrypted_message_len == NULL || ciphertext == NULL || key == NULL) return -1;

    const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const size_t mac_len = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    
    if (ciphertext_len < nonce_len + mac_len) return -1;

    // The maximum possible plaintext length is ciphertext length minus nonce and mac overhead
    size_t expected_plaintext_len = ciphertext_len - nonce_len - mac_len;
    
    // [FIX]: Output buffer boundary check
    if (decrypted_message_max_len < expected_plaintext_len) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "AEAD Decrypt: Output buffer too small. Required: %zu, Provided: %zu", expected_plaintext_len, decrypted_message_max_len);
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

int encrypt_symmetric_aead_detached(unsigned char* ciphertext, size_t ciphertext_max_len,
                                    unsigned char* tag_out, size_t tag_max_len,
                                    const unsigned char* message, size_t message_len, // [FIX] Added const
                                    const unsigned char* additional_data, size_t ad_len,
                                    unsigned char* nonce_out, size_t nonce_max_len,
                                    const unsigned char* key) {
    if (ciphertext == NULL || tag_out == NULL || message == NULL || nonce_out == NULL || key == NULL) return -1;
    
    // [FIX] Validate buffer sizes
    if (ciphertext_max_len < message_len) return -1;
    if (tag_max_len < crypto_aead_xchacha20poly1305_ietf_ABYTES) return -1;
    if (nonce_max_len < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) return -1;

    randombytes_buf(nonce_out, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    unsigned long long ciphertext_len_out;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            ciphertext, tag_out, &ciphertext_len_out,
            message, message_len, additional_data, ad_len, NULL, nonce_out, key
        ) != 0) {
        return -1;
    }
    return 0;
}

int decrypt_symmetric_aead_detached(unsigned char* decrypted_message, size_t decrypted_message_max_len,
                                    const unsigned char* ciphertext, size_t ciphertext_len,
                                    const unsigned char* tag,
                                    const unsigned char* additional_data, size_t ad_len,
                                    const unsigned char* nonce, const unsigned char* key) {
    if (decrypted_message == NULL || ciphertext == NULL || tag == NULL || nonce == NULL || key == NULL) return -1;
    
    // [FIX] Validate buffer size
    if (decrypted_message_max_len < ciphertext_len) return -1;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            decrypted_message, NULL,
            ciphertext, ciphertext_len,
            tag, additional_data, ad_len, nonce, key
        ) != 0) {
        return -1;
    }
    return 0;
}

// 重构：Authenticated Ephemeral KEM (Sign-then-Encrypt)
// [SECURITY FIX 2025]: 修复 Unknown Key Share 漏洞。
// 将接收方的加密公钥 (recipient_encrypt_pk) 纳入签名上下文，以绑定身份。
int encapsulate_session_key(unsigned char* encrypted_output,
                            size_t encrypted_output_max_len,
                            size_t* encrypted_output_len,
                            const unsigned char* session_key, size_t session_key_len,
                            const unsigned char* recipient_sign_pk,
                            const master_key_pair* sender_mkp) {
    
    if (encrypted_output == NULL || encrypted_output_len == NULL || session_key == NULL || 
        recipient_sign_pk == NULL || sender_mkp == NULL || sender_mkp->identity_sk == NULL) {
        return -1;
    }

    // [FIX]: Calculate required length and check bounds
    // Structure: [Nonce (24)] + [Ephemeral_PK (32)] + [Signature (64)] + [Ciphertext (SessionKey + 16)]
    size_t ciphertext_len = session_key_len + crypto_box_curve25519xchacha20poly1305_MACBYTES;
    size_t required_len = crypto_box_curve25519xchacha20poly1305_NONCEBYTES + 
                          crypto_box_PUBLICKEYBYTES + 
                          crypto_sign_BYTES + 
                          ciphertext_len;

    if (encrypted_output_max_len < required_len) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "Encapsulate: Output buffer too small. Required: %zu, Provided: %zu", required_len, encrypted_output_max_len);
        return -1;
    }

    // 1. 转换接收者的公钥 (Ed25519 PK -> X25519 PK)
    unsigned char recipient_encrypt_pk[crypto_box_PUBLICKEYBYTES];
    if (crypto_sign_ed25519_pk_to_curve25519(recipient_encrypt_pk, recipient_sign_pk) != 0) {
        return -1;
    }

    // 2. 生成临时密钥对 (Ephemeral Key Pair)
    unsigned char ephem_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char ephem_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(ephem_pk, ephem_sk);

    // 3. 生成 Nonce
    unsigned char nonce[crypto_box_curve25519xchacha20poly1305_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    // 4. 执行匿名加密 (使用 Ephemeral SK)
    // 使用安全内存临时存储密文，因为接下来要对其签名
    unsigned char* ciphertext = secure_alloc(ciphertext_len);
    if (!ciphertext) {
        sodium_memzero(ephem_sk, sizeof(ephem_sk));
        return -1;
    }

    if (crypto_box_curve25519xchacha20poly1305_easy(
            ciphertext,
            session_key, session_key_len,
            nonce,
            recipient_encrypt_pk,
            ephem_sk) != 0) {
        secure_free(ciphertext);
        sodium_memzero(ephem_sk, sizeof(ephem_sk));
        return -1;
    }
    
    // 立即擦除临时私钥
    sodium_memzero(ephem_sk, sizeof(ephem_sk));

    // 5. [FIX] 签名数据 (Sign-then-Encrypt)
    // 签名内容更新: [Nonce] || [Ephemeral_PK] || [Ciphertext] || [Recipient_Encrypt_PK]
    // 新增 Recipient_Encrypt_PK (32 bytes) 以锁定接收者身份，防止中间人重放。
    size_t msg_to_sign_len = sizeof(nonce) + sizeof(ephem_pk) + ciphertext_len + sizeof(recipient_encrypt_pk);
    unsigned char* msg_to_sign = secure_alloc(msg_to_sign_len);
    if (!msg_to_sign) {
        secure_free(ciphertext);
        return -1;
    }

    unsigned char* p_sign = msg_to_sign;
    memcpy(p_sign, nonce, sizeof(nonce)); p_sign += sizeof(nonce);
    memcpy(p_sign, ephem_pk, sizeof(ephem_pk)); p_sign += sizeof(ephem_pk);
    memcpy(p_sign, ciphertext, ciphertext_len); p_sign += ciphertext_len;
    // [FIX] Append recipient PK
    memcpy(p_sign, recipient_encrypt_pk, sizeof(recipient_encrypt_pk)); 

    unsigned char signature[crypto_sign_BYTES];
    crypto_sign_detached(signature, NULL, msg_to_sign, msg_to_sign_len, sender_mkp->identity_sk);
    
    secure_free(msg_to_sign); // 清理待签名缓冲

    // 6. 组装最终输出
    // Output Format: [Nonce(24)] || [Ephemeral_PK(32)] || [Signature(64)] || [Ciphertext]
    unsigned char* p_out = encrypted_output;
    memcpy(p_out, nonce, sizeof(nonce)); p_out += sizeof(nonce);
    memcpy(p_out, ephem_pk, sizeof(ephem_pk)); p_out += sizeof(ephem_pk);
    memcpy(p_out, signature, sizeof(signature)); p_out += sizeof(signature);
    memcpy(p_out, ciphertext, ciphertext_len);
    
    *encrypted_output_len = required_len;

    secure_free(ciphertext);
    return 0;
}

// [FIX]: 重构：Authenticated Ephemeral KEM 解封装
int decapsulate_session_key(unsigned char* decrypted_output,
                            size_t decrypted_output_max_len,
                            const unsigned char* encrypted_input, size_t encrypted_input_len,
                            const unsigned char* my_enc_sk,
                            const unsigned char* sender_public_key) {

    if (decrypted_output == NULL || encrypted_input == NULL || my_enc_sk == NULL || sender_public_key == NULL) {
        return -1;
    }

    // 1. 验证最小长度
    // Nonce(24) + Ephemeral_PK(32) + Signature(64) + MAC(16) = 136 bytes min
    size_t min_len = crypto_box_curve25519xchacha20poly1305_NONCEBYTES + 
                     crypto_box_PUBLICKEYBYTES + 
                     crypto_sign_BYTES + 
                     crypto_box_curve25519xchacha20poly1305_MACBYTES;
                     
    if (encrypted_input_len < min_len) {
        return -1;
    }

    // 2. 解析输入结构
    const unsigned char* nonce = encrypted_input;
    const unsigned char* ephem_pk = nonce + crypto_box_curve25519xchacha20poly1305_NONCEBYTES;
    const unsigned char* signature = ephem_pk + crypto_box_PUBLICKEYBYTES;
    const unsigned char* ciphertext = signature + crypto_sign_BYTES;
    
    size_t ciphertext_len = encrypted_input_len - (ciphertext - encrypted_input);
    size_t expected_plaintext_len = ciphertext_len - crypto_box_curve25519xchacha20poly1305_MACBYTES;

    // [FIX]: Check output buffer size
    if (decrypted_output_max_len < expected_plaintext_len) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "Decapsulate: Output buffer too small. Required: %zu, Provided: %zu", expected_plaintext_len, decrypted_output_max_len);
        return -1;
    }

    // 3. 验证签名
    // 重建被签名的消息: [Nonce] || [Ephemeral_PK] || [Ciphertext] || [My_Encrypt_PK]
    // 接收方需要知道自己的公钥 (X25519) 来验证发送方是否正确锁定了目标。
    
    unsigned char my_enc_pk[crypto_box_PUBLICKEYBYTES];
    crypto_scalarmult_base(my_enc_pk, my_enc_sk);

    size_t signed_msg_len = crypto_box_curve25519xchacha20poly1305_NONCEBYTES + 
                            crypto_box_PUBLICKEYBYTES + 
                            ciphertext_len +
                            crypto_box_PUBLICKEYBYTES; // Added Recipient PK length
                            
    unsigned char* signed_msg = secure_alloc(signed_msg_len);
    if (!signed_msg) {
        sodium_memzero(my_enc_pk, sizeof(my_enc_pk));
        return -1;
    }

    unsigned char* p_verify = signed_msg;
    memcpy(p_verify, nonce, crypto_box_curve25519xchacha20poly1305_NONCEBYTES); p_verify += crypto_box_curve25519xchacha20poly1305_NONCEBYTES;
    memcpy(p_verify, ephem_pk, crypto_box_PUBLICKEYBYTES); p_verify += crypto_box_PUBLICKEYBYTES;
    memcpy(p_verify, ciphertext, ciphertext_len); p_verify += ciphertext_len;
    // [FIX] Append my public key for verification
    memcpy(p_verify, my_enc_pk, crypto_box_PUBLICKEYBYTES);

    int verify_ret = crypto_sign_verify_detached(signature, signed_msg, signed_msg_len, sender_public_key);
    
    secure_free(signed_msg);
    sodium_memzero(my_enc_pk, sizeof(my_enc_pk)); // 清理推导出的公钥（虽然不是敏感数据，但保持干净）

    if (verify_ret != 0) {
        // 签名验证失败！
        // 可能是签名伪造，或者数据包被重放给了错误的接收者（Unknown Key Share 攻击）。
        _hsc_log(HSC_LOG_LEVEL_ERROR, "Security Alert: Sender signature verification failed (Identity Binding Mismatch). Aborting decryption.");
        return -1;
    }

    // 4. 执行解密 (My Static SK, Sender Ephemeral PK)
    int decrypt_ret = crypto_box_curve25519xchacha20poly1305_open_easy(
                    decrypted_output,
                    ciphertext, ciphertext_len,
                    nonce,
                    ephem_pk,  // 发送者的临时公钥
                    my_enc_sk); // 我的静态私钥

    return decrypt_ret;
}