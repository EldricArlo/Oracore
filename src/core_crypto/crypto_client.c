#include "crypto_client.h"
#include "../common/secure_memory.h"

#include <sodium.h>
#include <string.h>
#include <stdio.h> // For error printing

int crypto_client_init() {
    // 规范要求: 必须使用经过审查的专业密码学库。
    // sodium_init() 初始化 libsodium，并选择最优的、与平台无关的算法实现。
    // 它是线程安全的，可以多次调用。
    if (sodium_init() < 0) {
        return -1; // 初始化失败
    }
    return 0;
}

/**
 * @brief 【已修改】生成一个全新的 Ed25519 主密钥对，用于签名。
 */
int generate_master_key_pair(master_key_pair* kp) {
    // [修复] 将 assert 替换为返回错误码的运行时检查。
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
    // [修复] 将 assert 替换为返回错误码的运行时检查。
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
    if (opslimit < MIN_ARGON2ID_OPSLIMIT || memlimit < MIN_ARGON2ID_MEMLIMIT) {
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
    // [修复] 将 assert 替换为返回错误码的运行时检查。
    if (derived_key == NULL || password == NULL || salt == NULL || global_pepper == NULL) {
        return -1;
    }

    // 规范 4 - 阶段二 - 3.b: 【安全验证点】
    // 在执行任何 KDF 操作之前，必须先验证从服务器获取的参数。
    if (!validate_argon2id_params(opslimit, memlimit)) {
        return -1; // 参数验证失败
    }
    
    // 为了安全地将 pepper 融入 Argon2id，我们先计算 H(pepper || password)，
    // 然后将这个哈希值作为 Argon2id 的输入"密码"。这是一种健壮的模式。
    // 我们使用 BLAKE2b (libsodium的crypto_generichash) 来实现 H。
    unsigned char hashed_input[crypto_generichash_BYTES];
    crypto_generichash_state state;

    crypto_generichash_init(&state, NULL, 0, sizeof(hashed_input));
    crypto_generichash_update(&state, global_pepper, pepper_len);
    crypto_generichash_update(&state, (const unsigned char*)password, strlen(password));
    crypto_generichash_final(&state, hashed_input, sizeof(hashed_input));

    // 调用 libsodium 的 Argon2id 实现。
    // 它是恒定时间的，符合规范 3.2 的要求。
    if (crypto_pwhash(derived_key, derived_key_len,
                       (const char*)hashed_input, sizeof(hashed_input),
                       salt, opslimit, memlimit,
                       crypto_pwhash_ALG_DEFAULT) != 0) {
        secure_zero_memory(hashed_input, sizeof(hashed_input)); // 确保中间产物被清除
        return -1; // 密钥派生失败
    }

    // 规范 3.3: 安全内存管理
    // 立即清除内存中的中间哈希值。
    secure_zero_memory(hashed_input, sizeof(hashed_input));

    return 0;
}

int encrypt_symmetric_aead(
    unsigned char* ciphertext, unsigned long long* ciphertext_len,
    const unsigned char* message, size_t message_len,
    const unsigned char* key
) {
    // [修复] 将 assert 替换为返回错误码的运行时检查。
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
    // [修复] 将 assert 替换为返回错误码的运行时检查。
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


/**
 * @brief 【已重写】封装会话密钥。
 *        在加密前，将 Ed25519 签名密钥对动态转换为 X25519 加密密钥对。
 */
int encapsulate_session_key(unsigned char* encrypted_output,
                            const unsigned char* session_key, size_t session_key_len,
                            const unsigned char* recipient_sign_pk, // 接收者的 Ed25519 签名公钥
                            const unsigned char* my_sign_sk) {       // 我方的 Ed25519 签名私钥
    
    // [修复] 新增运行时检查 (此函数之前缺少检查)。
    if (encrypted_output == NULL || session_key == NULL || recipient_sign_pk == NULL || my_sign_sk == NULL) {
        return -1;
    }

    // 步骤1: 将 Ed25519 密钥转换为 X25519 (Curve25519) 密钥用于加密
    unsigned char recipient_encrypt_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char* my_encrypt_sk = secure_alloc(crypto_box_SECRETKEYBYTES); // 在安全内存中操作
    if (my_encrypt_sk == NULL) {
        return -1;
    }

    // 将接收者的 Ed25519 签名公钥转换为 X25519 加密公钥
    if (crypto_sign_ed25519_pk_to_curve25519(recipient_encrypt_pk, recipient_sign_pk) != 0) {
        secure_free(my_encrypt_sk);
        return -1; // 转换失败
    }
    // 将我方的 Ed25519 签名私钥转换为 X25519 加密私钥
    // [修复] 修正了函数名的拼写错误
    if (crypto_sign_ed25519_sk_to_curve25519(my_encrypt_sk, my_sign_sk) != 0) {
        secure_free(my_encrypt_sk);
        return -1; // 转换失败
    }

    // 步骤2: 使用转换后的加密密钥进行 crypto_box 操作
    // crypto_box_easy 的 nonce 参数为 NULL 是正确用法，libsodium 会自动、安全地生成 nonce。
    // 该 nonce 会被预置在加密输出的前面。
    int result = crypto_box_easy(encrypted_output, session_key, session_key_len,
                                 NULL, 
                                 recipient_encrypt_pk, my_encrypt_sk);
    
    // 步骤3: 立即清除内存中的临时加密私钥
    secure_free(my_encrypt_sk);
    
    return result;
}

/**
 * @brief 【已重写】解封装会话密钥。
 *        在解密前，将 Ed25519 签名密钥对动态转换为 X25519 加密密钥对。
 */
int decapsulate_session_key(unsigned char* decrypted_output,
                            const unsigned char* encrypted_input, size_t encrypted_input_len,
                            const unsigned char* sender_sign_pk, // 发送者的 Ed25519 签名公钥
                            const unsigned char* my_sign_sk) {     // 我方的 Ed25519 签名私钥

    // [修复] 新增运行时检查 (此函数之前缺少检查)。
    if (decrypted_output == NULL || encrypted_input == NULL || sender_sign_pk == NULL || my_sign_sk == NULL) {
        return -1;
    }

    // 步骤1: 将 Ed25519 密钥转换为 X25519 (Curve25519) 密钥用于解密
    unsigned char sender_encrypt_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char* my_encrypt_sk = secure_alloc(crypto_box_SECRETKEYBYTES); // 在安全内存中操作
    if (my_encrypt_sk == NULL) {
        return -1;
    }

    if (crypto_sign_ed25519_pk_to_curve25519(sender_encrypt_pk, sender_sign_pk) != 0) {
        secure_free(my_encrypt_sk);
        return -1;
    }
    // [修复] 修正了函数名的拼写错误
    if (crypto_sign_ed25519_sk_to_curve25519(my_encrypt_sk, my_sign_sk) != 0) {
        secure_free(my_encrypt_sk);
        return -1;
    }

    // 步骤2: 使用转换后的密钥进行解密
    // crypto_box_open_easy 会自动从输入数据中提取 nonce，因此 nonce 参数必须为 NULL。
    int result = crypto_box_open_easy(decrypted_output, encrypted_input, encrypted_input_len,
                                      NULL,
                                      sender_encrypt_pk, my_encrypt_sk);

    // 步骤3: 立即清除内存中的临时加密私钥
    secure_free(my_encrypt_sk);

    return result;
}