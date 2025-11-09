/**
 * @file crypto_client.c
 * @brief 核心密码学操作的实现。
 *
 * @details
 * 本文件是 libsodium 功能的核心封装层。它将 libsodium 提供的密码学原语
 * （如密钥生成、KDF、AEAD、密钥封装）适配为项目内部所需的接口。
 * 关键的安全决策，如算法选择、参数配置和敏感数据的内存管理，都在此文件中实现。
 */

#include "crypto_client.h"
#include "../common/secure_memory.h"

#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h> // 用于检查 strtoull 的范围错误

// --- 运行时安全参数的定义与初始化 ---
// 这些变量持有程序实际使用的 Argon2id 参数。
// 它们被初始化为编译时的基线值，确保在任何配置加载前都有一个安全的默认值。
unsigned long long g_argon2_opslimit = BASELINE_ARGON2ID_OPSLIMIT;
size_t g_argon2_memlimit = BASELINE_ARGON2ID_MEMLIMIT;


void crypto_config_load_from_env() {
    printf("Loading cryptographic parameters...\n");

    // --- 加载 Ops Limit ---
    const char* opslimit_env = getenv("HSC_ARGON2_OPSLIMIT");
    if (opslimit_env) {
        char* endptr;
        errno = 0; // 在调用 strtoull 之前必须重置 errno
        unsigned long long ops_from_env = strtoull(opslimit_env, &endptr, 10);

        // 健壮性检查:
        // 1. errno == ERANGE: 检查转换是否溢出。
        // 2. *endptr == '\0': 检查整个字符串是否都被成功解析。
        // 3. 值是否不低于基线: 核心安全要求。
        if (errno == ERANGE) {
            fprintf(stderr, "  > WARNING: HSC_ARGON2_OPSLIMIT value is out of range. Using default.\n");
        } else if (*endptr == '\0' && ops_from_env >= BASELINE_ARGON2ID_OPSLIMIT) {
            g_argon2_opslimit = ops_from_env;
            printf("  > Argon2id OpsLimit overridden by environment: %llu\n", g_argon2_opslimit);
        } else {
            fprintf(stderr, "  > WARNING: Invalid or below-baseline HSC_ARGON2_OPSLIMIT ignored. Using default.\n");
        }
    }

    // --- 加载 Mem Limit ---
    const char* memlimit_env = getenv("HSC_ARGON2_MEMLIMIT");
    if (memlimit_env) {
        char* endptr;
        errno = 0;
        unsigned long long mem_from_env = strtoull(memlimit_env, &endptr, 10);
        
        if (errno == ERANGE) {
            fprintf(stderr, "  > WARNING: HSC_ARGON2_MEMLIMIT value is out of range. Using default.\n");
        } else if (*endptr == '\0' && mem_from_env >= BASELINE_ARGON2ID_MEMLIMIT) {
            g_argon2_memlimit = (size_t)mem_from_env;
            printf("  > Argon2id MemLimit overridden by environment: %zu bytes\n", g_argon2_memlimit);
        } else {
            fprintf(stderr, "  > WARNING: Invalid or below-baseline HSC_ARGON2_MEMLIMIT ignored. Using default.\n");
        }
    }
    
    printf("  > Final effective Argon2id parameters: OpsLimit=%llu, MemLimit=%zu MB\n",
           g_argon2_opslimit, g_argon2_memlimit / (1024 * 1024));
}

int crypto_client_init() {
    // sodium_init() 初始化 libsodium，并选择最优的、与平台无关的算法实现。
    // 它是线程安全的，可以安全地多次调用。
    if (sodium_init() < 0) {
        return -1; // 初始化失败
    }

    // 初始化后立即从环境变量加载可配置参数
    crypto_config_load_from_env();
    
    return 0;
}

int generate_master_key_pair(master_key_pair* kp) {
    if (kp == NULL) {
        return -1;
    }

    // 规范 3.3: 私钥是最高价值的敏感数据，必须存储在受保护的内存中。
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
    // 规范 3.1: 客户端必须强制执行一个最小安全基线，防止降级攻击。
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
    if (derived_key == NULL || password == NULL || salt == NULL || global_pepper == NULL) {
        return -1;
    }

    // 规范 4 - 阶段二 - 3.b: 在执行任何 KDF 操作前，必须先验证参数。
    if (!validate_argon2id_params(opslimit, memlimit)) {
        return -1; // 参数验证失败
    }
    
    // 安全模式：为安全地将 pepper 融入 Argon2id，先计算 H(pepper || password)，
    // 然后将这个哈希值作为 Argon2id 的输入"密码"。这可以防止在某些罕见的
    // Argon2id 实现变体中可能出现的上下文问题。我们使用 BLAKE2b (libsodium 的默认通用哈希)。
    unsigned char hashed_input[crypto_generichash_BYTES];
    crypto_generichash_state state;

    crypto_generichash_init(&state, NULL, 0, sizeof(hashed_input));
    crypto_generichash_update(&state, global_pepper, pepper_len);
    crypto_generichash_update(&state, (const unsigned char*)password, strlen(password));
    crypto_generichash_final(&state, hashed_input, sizeof(hashed_input));

    // 调用 libsodium 的 Argon2id 实现。它是恒定时间的，符合规范 3.2 的要求。
    if (crypto_pwhash(derived_key, derived_key_len,
                       (const char*)hashed_input, sizeof(hashed_input), // 使用哈希后的值作为输入
                       salt, opslimit, memlimit,
                       crypto_pwhash_ALG_DEFAULT) != 0) {
        secure_zero_memory(hashed_input, sizeof(hashed_input)); // 确保中间产物被清除
        return -1; // 密钥派生失败
    }

    // 规范 3.3: 立即清除内存中的中间哈希值。
    secure_zero_memory(hashed_input, sizeof(hashed_input));

    return 0;
}

int encrypt_symmetric_aead(
    unsigned char* ciphertext, unsigned long long* ciphertext_len,
    const unsigned char* message, size_t message_len,
    const unsigned char* key
) {
    if (ciphertext == NULL || ciphertext_len == NULL || message == NULL || key == NULL) {
        return -1;
    }
    
    // 密文结构: [ nonce | 实际密文+认证标签 ]
    const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    unsigned char* nonce = ciphertext;
    unsigned char* actual_ciphertext = ciphertext + nonce_len;
    
    // 1. 生成一个密码学安全的、绝不重复的 Nonce
    randombytes_buf(nonce, nonce_len);
    
    // 2. 执行认证加密
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            actual_ciphertext, ciphertext_len, // 输出
            message, message_len,              // 输入
            NULL, 0, // 无附加数据 (AD)
            NULL,    // nsec (必须为NULL)
            nonce,   // 公共 nonce
            key
        ) != 0) {
        return -1; // 加密失败
    }

    // 3. 总长度 = 密文部分长度 + nonce 长度
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

    // 密文总长度必须至少包含一个完整的 nonce
    if (ciphertext_len < nonce_len) {
        return -1;
    }

    // 1. 从输入数据中拆分 nonce 和实际密文
    const unsigned char* nonce = ciphertext;
    const unsigned char* actual_ciphertext = ciphertext + nonce_len;
    const size_t actual_ciphertext_len = ciphertext_len - nonce_len;
    
    // 2. 执行认证解密。此函数会先验证认证标签，如果标签无效（数据被篡改或密钥错误），
    //    则函数会失败，并且绝不会写入任何解密数据。
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
        decrypted_message, decrypted_message_len, // 输出
        NULL, // nsec (必须为NULL)
        actual_ciphertext, actual_ciphertext_len, // 输入
        NULL, 0, // 无附加数据 (AD)
        nonce,   // 从密文中提取的 nonce
        key
    ) != 0) {
        return -1; // 解密/验证失败
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

    // --- 密钥转换: Ed25519 -> Curve25519 ---
    // Ed25519 用于签名，而 X25519 (libsodium中的crypto_box) 用于密钥交换/加密。
    // libsodium 提供了安全的方法将 Ed25519 密钥对转换为等效的 X25519 密钥对。
    // 这允许我们使用同一对主密钥来同时满足签名和加密的需求。
    
    unsigned char recipient_encrypt_pk[crypto_box_PUBLICKEYBYTES];
    if (crypto_sign_ed25519_pk_to_curve25519(recipient_encrypt_pk, recipient_sign_pk) != 0) {
        return -1; // 公钥转换失败
    }

    // 临时的 X25519 私钥是敏感数据，必须存储在安全内存中。
    unsigned char* my_encrypt_sk = secure_alloc(crypto_box_SECRETKEYBYTES);
    if (my_encrypt_sk == NULL) {
        return -1;
    }
    if (crypto_sign_ed25519_sk_to_curve25519(my_encrypt_sk, my_sign_sk) != 0) {
        secure_free(my_encrypt_sk);
        return -1; // 私钥转换失败
    }
    
    // --- 执行加密 ---
    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    // 输出格式: [ nonce | 加密数据+认证标签 ]
    unsigned char* ciphertext_ptr = encrypted_output + crypto_box_NONCEBYTES;
    
    int result = crypto_box_easy(ciphertext_ptr, session_key, session_key_len,
                                 nonce,
                                 recipient_encrypt_pk, my_encrypt_sk);
    
    // --- 清理与收尾 ---
    secure_free(my_encrypt_sk); // 立即擦除并释放临时的加密私钥

    if (result == 0) {
        // 将 nonce 复制到输出缓冲区的开头
        memcpy(encrypted_output, nonce, sizeof(nonce));
        // 总长度 = nonce + 会话密钥 + MAC
        *encrypted_output_len = crypto_box_NONCEBYTES + session_key_len + crypto_box_MACBYTES;
    } else {
        *encrypted_output_len = 0;
    }
    
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
        return -1; // 输入数据过短，无法包含 nonce
    }
    
    // 1. 拆分 nonce 和密文
    const unsigned char* nonce = encrypted_input;
    const unsigned char* actual_ciphertext = encrypted_input + crypto_box_NONCEBYTES;
    const size_t actual_ciphertext_len = encrypted_input_len - crypto_box_NONCEBYTES;

    // 2. 密钥转换 (Ed25519 -> Curve25519)
    unsigned char sender_encrypt_pk[crypto_box_PUBLICKEYBYTES];
    if (crypto_sign_ed25519_pk_to_curve25519(sender_encrypt_pk, sender_sign_pk) != 0) {
        return -1;
    }
    unsigned char* my_encrypt_sk = secure_alloc(crypto_box_SECRETKEYBYTES);
    if (my_encrypt_sk == NULL) {
        return -1;
    }
    if (crypto_sign_ed25519_sk_to_curve25519(my_encrypt_sk, my_sign_sk) != 0) {
        secure_free(my_encrypt_sk);
        return -1;
    }

    // 3. 执行认证解密
    int result = crypto_box_open_easy(decrypted_output, actual_ciphertext, actual_ciphertext_len,
                                      nonce,
                                      sender_encrypt_pk, my_encrypt_sk);

    // 4. 立即清理临时私钥
    secure_free(my_encrypt_sk);

    return result;
}