// --- START OF FILE include/hsc_kernel.h (FIXED) ---

#ifndef HSC_KERNEL_H
#define HSC_KERNEL_H

#include <stddef.h>
#include <stdbool.h>

// --- 公共常量 ---
#define HSC_MASTER_PUBLIC_KEY_BYTES 32
#define HSC_MASTER_SECRET_KEY_BYTES 64
#define HSC_SESSION_KEY_BYTES       32

// --- 公共数据结构 ---

/**
 * @brief 代表一个主密钥对。
 *        这是一个不透明的结构，其内部实现由内核库管理。
 */
typedef struct hsc_master_key_pair_s hsc_master_key_pair;


// --- 核心API函数 ---

/**
 * @brief 初始化整个高安全内核库。必须在使用任何其他API前调用。
 *        此函数是线程安全的。
 * @return 成功返回 0，失败返回 -1。
 */
int hsc_init();

/**
 * @brief 清理并释放内核库占用的所有全局资源。
 *        在程序退出前调用。
 */
void hsc_cleanup();


/**
 * @brief 生成一个全新的主密钥对。
 * @return 成功时返回指向新密钥对的指针，失败时返回 NULL。
 * @note 调用者必须稍后调用 hsc_free_master_key_pair 来释放此密钥对。
 */
hsc_master_key_pair* hsc_generate_master_key_pair();

/**
 * @brief [新] 从一个私钥文件安全地加载密钥对。
 *        公钥会从私钥中派生出来。
 * @param priv_key_path 指向私钥文件的路径。
 * @return 成功时返回指向新密钥对的指针，失败时返回 NULL。
 * @note 调用者必须稍后调用 hsc_free_master_key_pair 来释放此密钥对。
 */
hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(const char* priv_key_path);

/**
 * @brief [新] 将一个密钥对的公钥和私钥分别保存到文件中。
 * @param kp 指向要保存的密钥对。
 * @param pub_key_path 要写入的公钥文件路径。
 * @param priv_key_path 要写入的私钥文件路径。
 * @return 成功返回 0，失败返回 -1。
 */
int hsc_save_master_key_pair(const hsc_master_key_pair* kp, const char* pub_key_path, const char* priv_key_path);

/**
 * @brief 安全地释放由 hsc_generate_master_key_pair 或 hsc_load_master_key_pair_from_private_key 创建的密钥对。
 * @param kp 指向要释放的密钥对的指针。函数会将指针设置为NULL。
 */
void hsc_free_master_key_pair(hsc_master_key_pair** kp);

/**
 * @brief 生成证书签名请求 (CSR)。
 * @param mkp 指向已初始化的主密钥对的指针。
 * @param username 要嵌入到 CSR 主题中的用户名 (Common Name)。
 * @param out_csr_pem (输出) 指向一个 char 指针的指针。函数将分配内存
 *                    并存储 PEM 格式的 CSR 字符串。调用者必须负责
 *                    使用 hsc_free_pem_string() 释放这块内存。
 * @return 成功返回 0，失败返回 -1。
 */
int hsc_generate_csr(const hsc_master_key_pair* mkp, const char* username, char** out_csr_pem);

/**
 * @brief 释放由 hsc_generate_csr 分配的 PEM 字符串内存。
 * @param pem_string 指向要释放的 PEM 字符串的指针。
 */
void hsc_free_pem_string(char* pem_string);

/**
 * @brief 执行完整的证书验证流程。
 * @param user_cert_pem  要验证的用户证书 (PEM 格式)。
 * @param trusted_ca_cert_pem 客户端预置的、受信任的系统根 CA 证书 (PEM 格式)。
 * @param expected_username 期望从证书主体中找到的用户名 (Common Name)。
 * @return 0 如果所有验证步骤全部成功。
 *         -2 如果证书签名链或有效期验证失败。
 *         -3 如果证书主体 (Username) 不匹配。
 *         -4 如果证书已被吊销 (OCSP 检查失败)。
 *         -1 其他一般性错误。
 */
int hsc_verify_user_certificate(const char* user_cert_pem,
                                const char* trusted_ca_cert_pem,
                                const char* expected_username);
                                
/**
 * @brief 从一个 PEM 格式的用户证书中提取出原始的公钥字节。
 * @param user_cert_pem 要从中提取公钥的证书 (PEM 格式)。
 * @param public_key_out (输出) 一个缓冲区，用于存储提取出的原始公钥。
 *                       其大小必须至少为 HSC_MASTER_PUBLIC_KEY_BYTES。
 * @return 成功返回 0，失败返回 -1。
 */
int hsc_extract_public_key_from_cert(const char* user_cert_pem,
                                     unsigned char* public_key_out);

/**
 * @brief 封装会话密钥 (非对称加密)。
 * @param encrypted_output (输出) 存放加密结果的缓冲区。其大小必须足够大。
 * @param encrypted_output_len (输出) 指向一个变量的指针，用于存储最终输出的总长度。
 * @param session_key 要加密的会话密钥明文。
 * @param session_key_len 会话密钥的长度 (必须为 HSC_SESSION_KEY_BYTES)。
 * @param recipient_pk 接收者的 Ed25519 主公钥。
 * @param my_kp 我方（发送者）的完整密钥对。
 * @return 成功返回 0，失败返回 -1。
 */
int hsc_encapsulate_session_key(unsigned char* encrypted_output,
                                size_t* encrypted_output_len,
                                const unsigned char* session_key, size_t session_key_len,
                                const unsigned char* recipient_pk,
                                const hsc_master_key_pair* my_kp);

/**
 * @brief 解封装会话密钥 (非对称解密)。
 * @param decrypted_output (输出) 存放解密后的会话密钥的缓冲区。
 * @param encrypted_input 要解密的封装数据。
 * @param encrypted_input_len 封装数据的长度。
 * @param sender_pk 发送者的 Ed25519 主公钥。
 * @param my_kp 我方（接收者）的完整密钥对。
 * @return 成功返回 0，失败（如验证失败）返回 -1。
 */
int hsc_decapsulate_session_key(unsigned char* decrypted_output,
                                const unsigned char* encrypted_input, size_t encrypted_input_len,
                                const unsigned char* sender_pk,
                                const hsc_master_key_pair* my_kp);

#endif // HSC_KERNEL_H

// --- END OF FILE include/hsc_kernel.h (FIXED) ---