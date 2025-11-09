#ifndef PKI_HANDLER_H
#define PKI_HANDLER_H

#include "../core_crypto/crypto_client.h" // 需要用到 master_key_pair 结构

/**
 * @brief 初始化 PKI 子系统。必须在使用任何 PKI 功能前调用。
 *        主要作用是为 OpenSSL 3+ 加载算法提供者 (provider)。
 * @return 成功返回 0，失败返回 -1。
 */
int pki_init();

/**
 * @brief 规范 4 - 阶段一 - 4: 生成证书签名请求 (CSR)。
 *        此函数使用用户的主私钥来创建一个标准的 CSR，
 *        该 CSR 包含了主公钥和用户身份信息（用户名）。
 *
 * @param mkp 指向已初始化的主密钥对的指针。
 * @param username 要嵌入到 CSR 主题中的用户名 (Common Name)。
 * @param out_csr_pem (输出) 指向一个 char 指针的指针。函数将分配内存
 *                    并存储 PEM 格式的 CSR 字符串。调用者必须负责
 *                    使用 free_csr_pem() 释放这块内存。
 * @return 成功返回 0，失败返回 -1。
 */
int generate_csr(const master_key_pair* mkp, const char* username, char** out_csr_pem);

/**
 * @brief 释放由 generate_csr 分配的 PEM 字符串内存。
 * @param csr_pem 指向要释放的 CSR PEM 字符串的指针。
 */
void free_csr_pem(char* csr_pem);


/**
 * @brief 规范 4 - 阶段三 - 2.b: 【客户端强制验证】
 *        执行完整的、标准的证书验证流程。
 *        此函数会检查：
 *        i.   签名链是否由受信任的 CA 签署。
 *        ii.  证书是否在有效期内。
 *        iii. 证书的 'Subject' 是否与预期用户匹配。
 *        iv.  (模拟) 证书的实时吊销状态。
 *
 * @param user_cert_pem  要验证的用户证书 (PEM 格式)。
 * @param trusted_ca_cert_pem 客户端预置的、受信任的系统根 CA 证书 (PEM 格式)。
 * @param expected_username 期望从证书主体中找到的用户名 (Common Name)。
 * @return 0 如果所有验证步骤全部成功。
 *         -1 如果发生一般性错误 (如内存分配、PEM 解析失败)。
 *         -2 如果证书签名链或有效期验证失败。
 *         -3 如果证书主体 (Username) 不匹配。
 *         -4 如果证书已被吊销 (OCSP 检查失败)。
 */
int verify_user_certificate(const char* user_cert_pem,
                            const char* trusted_ca_cert_pem,
                            const char* expected_username);

/**
 * @brief 从一个 PEM 格式的用户证书中提取出原始的公钥字节。
 *        这个函数应该在一个证书通过 verify_user_certificate 验证后被调用。
 *
 * @param user_cert_pem 要从中提取公钥的证书 (PEM 格式)。
 * @param public_key_out (输出) 一个缓冲区，用于存储提取出的原始公钥。
 *                       其大小必须至少为 MASTER_PUBLIC_KEY_BYTES。
 * @return 成功返回 0，失败返回 -1。
 */
int extract_public_key_from_cert(const char* user_cert_pem,
                                 unsigned char* public_key_out);

#endif // PKI_HANDLER_H