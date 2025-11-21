#ifndef CRYPTO_CLIENT_H
#define CRYPTO_CLIENT_H

#include "../common/security_spec.h"
#include <stdbool.h>
#include <stddef.h>

// --- 数据结构定义 ---

/**
 * @brief 主密钥对结构体 (重构版: 强制密钥分离)
 * 
 * [安全修复说明 - 密钥分离原则]
 * 原始设计中，同一个密钥同时用于 Ed25519 签名和 X25519 加密。
 * 现在的设计将它们在内存中强制隔离：
 * 1. Identity Key (Ed25519): 仅用于签署 CSR、证书验证等身份操作。
 * 2. Encryption Key (X25519): 仅用于密钥封装 (Key Encapsulation)。
 * 
 * [当前实现的限制与风险警告]
 * 虽然实现了内存隔离，但为了保持与现有 X.509 PKI 基础设施的兼容性，
 * encryption_sk 目前仍是在加载时通过数学转换从 identity_sk 派生的。
 * 这意味着如果 identity_sk 泄露，encryption_sk 也会泄露（缺乏完全的前向保密性）。
 * 未来的版本应考虑通过签名机制分发独立的、可轮换的加密子密钥。
 */
typedef struct master_key_pair_s {
    // --- 1. 身份与签名密钥 (Ed25519) ---
    unsigned char identity_pk[MASTER_PUBLIC_KEY_BYTES];
    // [敏感数据] 指向安全内存，仅用于 crypto_sign 操作
    unsigned char* identity_sk; 

    // --- 2. 数据加密密钥 (X25519) ---
    // 注意：在当前版本中，这是从 Identity Key 转换而来的。
    unsigned char encryption_pk[crypto_box_PUBLICKEYBYTES];
    // [敏感数据] 指向安全内存，仅用于 crypto_box/seal 操作
    unsigned char* encryption_sk; 
} master_key_pair;

// [修复] 为恢复密钥结构体添加了标签名 `recovery_key_s`，以保持一致性。
typedef struct recovery_key_s {
    unsigned char* key;
} recovery_key;


// --- 函数原型 ---

/**
 * @brief 从环境变量加载并验证密码学参数。
 *        此函数会读取如 HSC_ARGON2_OPSLIMIT 等环境变量，
 *        如果它们的值高于内置的安全基线，则使用它们，否则保持基线值。
 */
void crypto_config_load_from_env();

/**
 * @brief 初始化密码学库，必须在任何密码学操作前调用。
 * 
 * [FIX]: 更新函数签名以支持显式传入 Pepper。
 *        如果 explicit_pepper_hex 不为 NULL，则优先使用它。
 *        如果为 NULL，则回退尝试从环境变量加载，并尝试执行内存擦除。
 * 
 * @param explicit_pepper_hex 可选的显式传入的 Pepper 十六进制字符串。
 * @return 成功返回 0，失败返回 -1
 */
int crypto_client_init(const char* explicit_pepper_hex);

/**
 * @brief 清理密码学客户端分配的资源，如全局胡椒。
 *        应在程序退出前调用。
 */
void crypto_client_cleanup();

/**
 * @brief 获取已加载的全局胡椒。
 * @param out_len (输出) 用于存储胡椒长度的指针。
 * @return 指向存储在安全内存中的全局胡椒的常量指针。
 */
const unsigned char* get_global_pepper(size_t* out_len);

/**
 * @brief 生成一个全新的主密钥对
 *        [变更] 此函数现在会同时生成 Identity Key，并派生出隔离的 Encryption Key。
 * @param kp 指向 master_key_pair 结构体的指针，用于存储生成的密钥对
 * @return 成功返回 0，失败返回 -1。私钥存储在安全内存中
 */
int generate_master_key_pair(master_key_pair* kp);

/**
 * @brief 释放主密钥对占用的安全内存
 *        [变更] 会分别擦除 identity_sk 和 encryption_sk
 * @param kp 指向要释放的密钥对结构体
 */
void free_master_key_pair(master_key_pair* kp);

/**
 * @brief 生成一个全新的恢复密钥
 * @param rk 指向 recovery_key 结构体的指针，用于存储生成的密钥
 * @return 成功返回 0，失败返回 -1。密钥存储在安全内存中
 */
int generate_recovery_key(recovery_key* rk);

/**
 * @brief 释放恢复密钥占用的安全内存
 * @param rk 指向要释放的恢复密钥结构体
 */
void free_recovery_key(recovery_key* rk);


/**
 * @brief 规范 3.1: 验证从服务器获取的 Argon2id 参数是否不低于内置的安全基线
 * @param opslimit 服务器提供的 opslimit 参数
 * @param memlimit 服务器提供的 memlimit 参数
 * @return 如果参数安全则返回 true，否则返回 false
 */
bool validate_argon2id_params(unsigned long long opslimit, size_t memlimit);

/**
 * @brief 从用户密码、盐和胡椒派生出加密密钥
 *        此函数严格遵循规范，在派生前会校验安全参数
 *
 * @param derived_key (输出) 指向存储派生密钥的缓冲区的指针
 * @param derived_key_len 期望的派生密钥长度
 * @param password 用户输入的密码
 * @param salt 用户盐值
 * @param opslimit Argon2id 的操作限制参数
 * @param memlimit Argon2id 的内存限制参数
 * @param global_pepper 全局胡椒
 * @param pepper_len 胡椒的长度
 * @return 成功返回 0，如果参数校验失败或派生失败则返回 -1
 */
int derive_key_from_password(
    unsigned char* derived_key, size_t derived_key_len,
    const char* password,
    const unsigned char* salt,
    unsigned long long opslimit, size_t memlimit,
    const unsigned char* global_pepper, size_t pepper_len
);

/**
 * @brief 使用 AEAD (XChaCha20-Poly1305) 对称加密数据
 *
 * @param ciphertext (输出) 加密后的数据缓冲区
 * @param ciphertext_len (输出) 加密后数据的长度
 * @param message 要加密的明文
 * @param message_len 明文的长度
 * @param key 加密密钥
 * @return 成功返回 0，失败返回 -1
 */
int encrypt_symmetric_aead(
    unsigned char* ciphertext, unsigned long long* ciphertext_len,
    const unsigned char* message, size_t message_len,
    const unsigned char* key
);

/**
 * @brief 使用 AEAD (XChaCha20-Poly1305) 对称解密数据
 *
 * @param decrypted_message (输出) 解密后的明文缓冲区
 * @param decrypted_message_len (输出) 解密后明文的长度
 * @param ciphertext 要解密的密文
 * @param ciphertext_len 密文的长度
 * @param key 解密密钥
 * @return 成功返回 0，失败（如验证失败）返回 -1
 */
int decrypt_symmetric_aead(
    unsigned char* decrypted_message, unsigned long long* decrypted_message_len,
    const unsigned char* ciphertext, size_t ciphertext_len,
    const unsigned char* key
);

/**
 * @brief [分离模式] 内部实现 AEAD 对称加密
 */
int encrypt_symmetric_aead_detached(unsigned char* ciphertext, unsigned char* tag_out,
                                    const unsigned char* message, size_t message_len,
                                    const unsigned char* additional_data, size_t ad_len,
                                    const unsigned char* nonce, const unsigned char* key);

/**
 * @brief [分离模式] 内部实现 AEAD 对称解密
 */
int decrypt_symmetric_aead_detached(unsigned char* decrypted_message,
                                    const unsigned char* ciphertext, size_t ciphertext_len,
                                    const unsigned char* tag,
                                    const unsigned char* additional_data, size_t ad_len,
                                    const unsigned char* nonce, const unsigned char* key);


/**
 * @brief 规范 4 - 阶段三 - 4: 封装会话密钥 (非对称加密)
 *        使用我方的私钥和接收者的公钥，加密一个会话密钥
 *        输出格式为 [nonce || encrypted_key]，其中 nonce 长度为 crypto_box_NONCEBYTES
 * 
 *        [修复] 参数更新:
 *        @param my_sign_sk 现已弃用，应传入明确的 encryption_sk
 *
 * @param encrypted_output (输出) 存放加密结果的缓冲区
 * @param encrypted_output_len (输出) 指向一个变量的指针，用于存储最终输出的总长度
 * @param session_key 要加密的会话密钥明文
 * @param session_key_len 会话密钥的长度
 * @param recipient_sign_pk 接收者的 Ed25519 主公钥 (函数内部会处理到 X25519 的转换)
 * @param my_enc_sk 我方（发送者）的 X25519 加密私钥 (对应 master_key_pair.encryption_sk)
 * @return 成功返回 0，失败返回 -1
 */
int encapsulate_session_key(unsigned char* encrypted_output,
                            size_t* encrypted_output_len,
                            const unsigned char* session_key, size_t session_key_len,
                            const unsigned char* recipient_sign_pk,
                            const unsigned char* my_enc_sk);

/**
 * @brief 解封装会话密钥 (非对称解密)
 *        使用我方的私钥和发送者的公钥，解密一个会话密钥
 *        输入数据格式应为 [nonce || encrypted_key]
 * 
 *        [修复] 参数更新:
 *        @param my_sign_sk 现已弃用，应传入明确的 encryption_sk
 *
 * @param decrypted_output (输出) 存放解密后的会-话密钥的缓冲区
 * @param encrypted_input 要解密的封装数据
 * @param encrypted_input_len 封装数据的长度
 * @param sender_sign_pk 发送者的 Ed25519 主公钥 (函数内部会处理到 X25519 的转换)
 * @param my_enc_sk 我方（接收者）的 X25519 加密私钥 (对应 master_key_pair.encryption_sk)
 * @return 成功返回 0，失败（如验证失败）返回 -1
 */
int decapsulate_session_key(unsigned char* decrypted_output,
                            const unsigned char* encrypted_input, size_t encrypted_input_len,
                            const unsigned char* sender_sign_pk,
                            const unsigned char* my_enc_sk);


#endif // CRYPTO_CLIENT_H