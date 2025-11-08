#include "crypto_client.h"
#include "../common/secure_memory.h"

#include <sodium.h>
#include <string.h>
#include <stdio.h>

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
    // 将 assert 替换为返回错误码的运行时检查。
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

/**
 * @brief 封装会话密钥。
 *        此函数现在会正确处理 nonce，将其预置在密文之前。
 *        输出格式为: [nonce || 密文]
 *
 * @param encrypted_output (输出) 缓冲区，必须足够大以容纳 nonce 和加密后的密钥。
 *                         建议大小: crypto_box_NONCEBYTES + session_key_len + crypto_box_MACBYTES
 * @param encrypted_output_len (输出) 指向一个变量的指针，用于存储最终输出的总长度。
 * @param session_key 要加密的会话密钥。
 * @param session_key_len 会话密钥的长度。
 * @param recipient_sign_pk 接收者的 Ed25519 签名公钥。
 * @param my_sign_sk 我方的 Ed25519 签名私钥。
 * @return 成功返回 0，失败返回 -1。
 */
int encapsulate_session_key(unsigned char* encrypted_output,
                            size_t* encrypted_output_len,
                            const unsigned char* session_key, size_t session_key_len,
                            const unsigned char* recipient_sign_pk,
                            const unsigned char* my_sign_sk) {
    
    if (encrypted_output == NULL || encrypted_output_len == NULL || session_key == NULL || recipient_sign_pk == NULL || my_sign_sk == NULL) {
        return -1;
    }

    // 步骤1: 将 Ed25519 密钥转换为 X25519 (Curve25519) 密钥用于加密
    unsigned char recipient_encrypt_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char* my_encrypt_sk = secure_alloc(crypto_box_SECRETKEYBYTES); // 在安全内存中操作
    if (my_encrypt_sk == NULL) {
        return -1;
    }

    if (crypto_sign_ed25519_pk_to_curve25519(recipient_encrypt_pk, recipient_sign_pk) != 0) {
        secure_free(my_encrypt_sk);
        return -1; // 转换失败
    }
    if (crypto_sign_ed25519_sk_to_curve25519(my_encrypt_sk, my_sign_sk) != 0) {
        secure_free(my_encrypt_sk);
        return -1; // 转换失败
    }
    
    // 步骤2: 生成一个随机的、一次性的 nonce
    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    // 步骤3: 使用转换后的密钥和生成的 nonce 进行 crypto_box 操作
    // 我们将密文写入到 nonce 之后的位置
    unsigned char* ciphertext_ptr = encrypted_output + crypto_box_NONCEBYTES;
    
    int result = crypto_box_easy(ciphertext_ptr, session_key, session_key_len,
                                 nonce, // <-- [核心修复] 显式传递唯一的 nonce
                                 recipient_encrypt_pk, my_encrypt_sk);
    
    // 步骤4: 如果加密成功，将 nonce 复制到输出缓冲区的开头
    if (result == 0) {
        memcpy(encrypted_output, nonce, sizeof(nonce));
        *encrypted_output_len = crypto_box_NONCEBYTES + session_key_len + crypto_box_MACBYTES;
    } else {
        *encrypted_output_len = 0;
    }

    // 步骤5: 立即清除内存中的临时加密私钥
    secure_free(my_encrypt_sk);
    
    return result;
}

/**
 * @brief 解封装会话密钥。
 *        此函数现在会从输入数据中正确提取 nonce 进行解密。
 *        输入格式应为: [nonce || 密文]
 *
 * @param decrypted_output (输出) 存放解密后的会话密钥的缓冲区。
 * @param encrypted_input 要解密的封装数据。
 * @param encrypted_input_len 封装数据的长度。
 * @param sender_sign_pk 发送者的 Ed25519 签名公钥。
 * @param my_sign_sk 我方的 Ed25519 签名私钥。
 * @return 成功返回 0，失败（如验证失败）返回 -1。
 */
int decapsulate_session_key(unsigned char* decrypted_output,
                            const unsigned char* encrypted_input, size_t encrypted_input_len,
                            const unsigned char* sender_sign_pk,
                            const unsigned char* my_sign_sk) {

    if (decrypted_output == NULL || encrypted_input == NULL || sender_sign_pk == NULL || my_sign_sk == NULL) {
        return -1;
    }

    // 步骤1: 验证输入长度是否足够包含一个 nonce
    if (encrypted_input_len < crypto_box_NONCEBYTES) {
        return -1; // 输入数据过短，无法包含 nonce
    }
    
    // 步骤2: 从输入数据中提取 nonce 和实际的密文
    const unsigned char* nonce = encrypted_input;
    const unsigned char* actual_ciphertext = encrypted_input + crypto_box_NONCEBYTES;
    const size_t actual_ciphertext_len = encrypted_input_len - crypto_box_NONCEBYTES;

    // 步骤3: 将 Ed25519 密钥转换为 X25519 (Curve25519) 密钥用于解密
    unsigned char sender_encrypt_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char* my_encrypt_sk = secure_alloc(crypto_box_SECRETKEYBYTES); // 在安全内存中操作
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

    // 步骤4: 使用提取的 nonce 和转换后的密钥进行解密
    int result = crypto_box_open_easy(decrypted_output, actual_ciphertext, actual_ciphertext_len,
                                      nonce, // <-- [核心修复] 显式传递从输入中提取的 nonce
                                      sender_encrypt_pk, my_encrypt_sk);

    // 步骤5: 立即清除内存中的临时加密私钥
    secure_free(my_encrypt_sk);

    return result;
}