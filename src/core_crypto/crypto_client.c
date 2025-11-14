// --- crypto_client.c (REVISED BY COMMITTEE FOR LOGGING CALLBACK) ---
#include "crypto_client.h"
#include "../common/secure_memory.h"
#include "../common/internal_logger.h" // [COMMITTEE FIX] 引入内部日志头文件

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
    // 将 assert 替换为返回错误码的运行时检查。
    if (kp == NULL) {
        return -1;
    }

    // 规范 3.3: 安全内存管理
    // 私钥是最高价值的敏感数据，必须存储在受保护的内存中。
    kp->sk = secure_alloc(MASTER_SECRET_KEY_BYTES);
    if (kp->sk == NULL) {
        return -1; // 内存分配失败
    }

    // 使用 crypto_sign_keypair 生成 Ed25519 密钥对，专门用于数字签名。
    crypto_sign_keypair(kp->pk, kp->sk);

    return 0;
}

void free_master_key_pair(master_key_pair* kp) {
    if (kp != NULL && kp->sk != NULL) {
        // secure_free 会在释放前安全地擦除内存，防止敏感数据残留。
        secure_free(kp->sk);
        kp->sk = NULL;
    }
}

int generate_recovery_key(recovery_key* rk) {
    // 将 assert 替换为返回错误码的运行时检查。
    if (rk == NULL) {
        return -1;
    }

    // 同样，恢复密钥也必须存储在安全内存中。
    rk->key = secure_alloc(RECOVERY_KEY_BYTES);
    if (rk->key == NULL) {
        return -1;
    }

    // 使用密码学安全的伪随机数生成器填充密钥。
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
    // 规范 3.1: 抗降级攻击
    // 客户端必须强制执行一个最小安全基线。
    // 此函数现在总是与编译时定义的 BASELINE_ 宏进行比较，
    // 以确保无论运行时配置如何，它都能拒绝来自外部的、低于绝对安全底线的值。
    if (opslimit < BASELINE_ARGON2ID_OPSLIMIT || memlimit < BASELINE_ARGON2ID_MEMLIMIT) {
        return false; // 参数低于内置基线，拒绝执行！
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
    // 将 assert 替换为返回错误码的运行时检查。
    if (derived_key == NULL || password == NULL || salt == NULL || global_pepper == NULL) {
        return -1;
    }

    int ret = -1; // 默认返回失败
    // [安全修复 CRITICAL] 使用安全内存分配中间哈希值
    unsigned char* hashed_input = NULL;

    // 规范 4 - 阶段二 - 3.b: 【安全验证点】
    // 在执行任何 KDF 操作之前，必须先验证从服务器获取的参数。
    if (!validate_argon2id_params(opslimit, memlimit)) {
        goto cleanup; // 参数验证失败
    }
    
    // 为了安全地将 pepper 融入 Argon2id，我们先计算 H(pepper || password)，
    // 然后将这个哈希值作为 Argon2id 的输入"密码"。这是一种健壮的模式。
    // 我们使用 BLAKE2b (libsodium的crypto_generichash) 来实现 H。
    hashed_input = secure_alloc(crypto_generichash_BYTES);
    if (!hashed_input) { goto cleanup; }

    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, crypto_generichash_BYTES);
    crypto_generichash_update(&state, global_pepper, pepper_len);
    crypto_generichash_update(&state, (const unsigned char*)password, strlen(password));
    crypto_generichash_final(&state, hashed_input, crypto_generichash_BYTES);

    // 调用 libsodium 的 Argon2id 实现。
    // 它是恒定时间的，符合规范 3.2 的要求。
    if (crypto_pwhash(derived_key, derived_key_len,
                       (const char*)hashed_input, crypto_generichash_BYTES,
                       salt, opslimit, memlimit,
                       crypto_pwhash_ALG_DEFAULT) != 0) {
        goto cleanup; // 密钥派生失败
    }

    ret = 0; // 所有操作成功

cleanup:
    // 规范 3.3: 安全内存管理
    // 立即清除内存中的中间哈希值。
    // secure_free 会自动擦除内存。
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
    // 将 assert 替换为返回错误码的运行时检查。
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
            NULL, 0, // 无附加数据(AD)
            NULL,    // nsec (必须为NULL)
            nonce,   // 公共 nonce
            key
        ) != 0) {
        return -1; // 加密失败
    }

    *ciphertext_len += nonce_len;
    
    return 0;
}

int decrypt_symmetric_aead(
    unsigned char* decrypted_message, unsigned long long* decrypted_message_len,
    const unsigned char* ciphertext, size_t ciphertext_len,
    const unsigned char* key
) {
    // 将 assert 替换为返回错误码的运行时检查。
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
        NULL, // nsec (必须为NULL)
        actual_ciphertext, actual_ciphertext_len,
        NULL, 0, // 无附加数据(AD)
        nonce,   // 从密文中提取的公共 nonce
        key
    ) != 0) {
        return -1; // 解密失败
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