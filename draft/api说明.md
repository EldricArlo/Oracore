好的，委员会已收到您的请求。我们将就 "Oracipher Core" 项目的公共API（`hsc_kernel.h`）设计进行一次专项审查，重点讨论API的暴露策略。

在开始之前，委员会必须首先阐明一个核心设计哲学：**在高安全性库中，API的设计目标是“约束”而非“解放”。** 一个优秀的安全性API应该像一条铺设了护栏的道路，它通过限制用户的选择来从根本上消除误用的可能性。给予用户过多的底层选择，往往会无意中提供“安全脚手架”之外的“悬崖小径”，从而违背了库的设计初衷。

我们的分析将严格围绕这一哲学，在“提供必要灵活性”与“绝不牺牲安全性”之间寻求最佳平衡。

---

### **API暴露策略专项审查报告**

---

### **第一部分：绝对禁止暴露的内部API (Pillars of Internal Integrity)**

以下内部函数/模块构成了库安全模型的基石。将它们直接暴露给最终用户将是**灾难性的**，因为它会破坏库的核心安全保证（如内存安全、协议完整性、安全默认等）。

| 内部函数/模块 | 位置 | 绝对禁止暴露的原因 |
| :--- | :--- | :--- |
| **`derive_key_from_password`** | `crypto_client.c` | **风险：致命 (Critical)**。此函数是密码学应用中最容易被误用的部分之一。它接收多个关键安全参数（`opslimit`, `memlimit`, `salt`, `pepper`）。直接暴露它会导致：<br>1. **参数选择不当**：用户可能为了性能而选择低于安全基线的`opslimit`和`memlimit`，导致密钥派生强度不足。<br>2. **胡椒(Pepper)误用/遗忘**：用户可能忘记或错误地实现`H(pepper || password)`的预处理步骤，从而完全丧失胡椒提供的安全保护。<br>3. **盐(Salt)管理混乱**：用户可能重用盐值，或使用质量不高的随机数生成盐。<br>**结论：** KDF的复杂性必须被库完全封装。 |
| **OCSP检查的系列辅助函数** | `pki_handler.c` | **风险：高 (High)**。像 `_create_ocsp_request`, `perform_http_post`, `_verify_and_check_status` 等函数是实现`hsc_verify_user_certificate`的内部状态机。暴露这些碎片化的步骤，等于要求用户手动、正确地执行整个OCSP验证流程。这极易导致：<br>1. **状态机错误**：用户可能跳过某一步（如签名验证）或错误处理了网络异常。<br>2. **绕过“故障关闭”**：用户可能会在网络请求失败时选择“继续”，从而违背了项目最核心的“故障关闭”原则。<br>**结论：** 证书验证必须是一个原子性的、不可分割的操作。 |
| **`crypto_config_load_from_env`** | `crypto_client.c` | **风险：中 (Medium)**。这是一个内部初始化函数，用于在库启动时建立安全参数基线。暴露它会：<br>1. **破坏封装**：库的配置管理是其内部事务。<br>2. **引发混乱**：用户可能会在程序运行中途调用它，试图改变安全参数，但这可能不是线程安全的，也不是设计的预期行为，会导致状态不一致。<br>**结论：** 配置加载应在`hsc_init()`中自动完成，对用户透明。 |
| **`_hsc_log`** | `hsc_kernel.c` | **风险：低 (Low)**。暴露日志**实现**函数是错误的设计模式。正确的模式（已实现）是暴露一个**注册**函数 (`hsc_set_log_callback`)，让用户注入他们自己的日志处理器。这遵循了“控制反转”(Inversion of Control)原则，实现了库与客户端应用的解耦。<br>**结论：** 当前的日志API设计是正确的，不应改动。 |

---

### **第二部分：有必要/可考虑暴露的新API (Controlled Flexibility)**

分析您当前的需求，委员会认为可以在不破坏安全模型的前提下，新增一些“专家级”API，为高级用户提供更多选择。这些API应该被明确标记，并附有严格的使用警告。

| 建议新增的API | 目的与价值 | 安全性考量与实现要点 |
| :--- | :--- | :--- |
| **密钥转换函数** | **目的**：允许高级用户将一个Ed25519密钥对安全地转换为X25519密钥对，用于实现其他基于密钥封装的协议。<br>**价值**：当前库内部在`encapsulate_session_key`中隐式地执行了此操作。将其显式化，可以增加库的通用性。 | **安全性**：此操作本身是安全的，由Libsodium的标准函数保证。风险在于用户如何管理转换后的密钥。<br>**实现要点**：提供两个新函数 `hsc_convert_ed25519_pk_to_x25519_pk` 和 `hsc_convert_ed25519_sk_to_x25519_sk`。它们应该是纯粹的计算函数，不涉及内存分配。 |
| **“分离模式”的AEAD加解密** | **目的**：为需要自行管理Nonce和认证标签(Tag)的高级网络协议提供支持。<br>**价值**：当前的`hsc_aead_encrypt`将Nonce和密文打包在一起，格式固定。分离模式提供更大的灵活性，允许用户将Nonce、密文、Tag存储在数据包的不同字段中。 | **安全性：风险极高 (High)**。**Nonce重用在XChaCha20-Poly1305中是毁灭性的，会导致密钥泄露**。因此，这个API必须附带最严厉的警告。<br>**实现要点**：提供 `hsc_aead_encrypt_detached` 和 `hsc_aead_decrypt_detached`。它们将接收Nonce作为输入参数，并将密文和Tag作为独立的输出。**必须在头文件的文档中用大写和粗体字强调Nonce绝不能重用的危险。** |
| **更安全的KDF函数** | **目的**：满足用户使用项目认可的KDF算法派生其他类型密钥的需求（例如，派生用于数据库加密的密钥）。<br>**价值**：直接暴露`derive_key_from_password`是危险的，但完全不提供KDF功能又限制了库的用途。我们可以提供一个“受约束”的版本。 | **安全性**：关键在于**不能让用户选择安全参数**。新的API必须在内部使用由`hsc_init()`确定的、经过基线验证的全局`g_argon2_opslimit`和`g_argon2_memlimit`参数。<br>**实现要点**：新增`hsc_derive_key_from_password`。此函数接收密码和盐，但**不接收**`opslimit`和`memlimit`。它应该在内部处理胡椒逻辑，确保用户无法绕过它。 |

---

### **第三部分：改进方案 (Proposed `hsc_kernel.h` Revision)**

基于以上分析，委员会提出对`hsc_kernel.h`进行如下修订。此修订方案在保持现有API稳定的基础上，审慎地增加了专家级功能。

```c
// hsc_kernel.h (REVISED BY COMMITTEE FOR API EXPOSURE)

#ifndef HSC_KERNEL_H
#define HSC_KERNEL_H

// ... (现有宏定义、错误码、不透明指针等保持不变) ...

// --- 核心API函数：初始化与密钥管理 ---
// ... (hsc_init, hsc_cleanup, hsc_generate_master_key_pair 等保持不变) ...

// --- 核心API函数：PKI 与证书 ---
// ... (hsc_generate_csr, hsc_verify_user_certificate 等保持不变) ...

// --- 核心API函数：密钥封装 (非对称) ---
// ... (hsc_encapsulate_session_key, hsc_decapsulate_session_key 保持不变) ...

// --- 核心API函数：流式加解密 (适用于大文件) ---
// ... (hsc_crypto_stream_state_new_push 等保持不变) ...

// --- 核心API函数：高级混合加解密 (原始密钥模式) ---
// ... (hsc_hybrid_encrypt_stream_raw, hsc_hybrid_decrypt_stream_raw 保持不变) ...

// --- 核心API函数：单次对称加解密 (适用于小数据) ---
// ... (hsc_aead_encrypt, hsc_aead_decrypt 保持不变) ...

// --- 核心API函数：安全内存管理 ---
// ... (hsc_secure_alloc, hsc_secure_free 保持不变) ...

// --- 核心API函数：日志回调管理 ---
// ... (hsc_set_log_callback 保持不变) ...


// =======================================================================
// --- [新增] 专家级API (EXPERT-LEVEL APIS) ---
// 警告：以下函数为高级用户设计，需要调用者对密码学概念有深入理解。
//      不当使用这些函数可能导致严重的安全漏洞。
// =======================================================================

/**
 * @brief [专家级] 从用户密码和盐安全地派生密钥。
 *        此函数使用库内部配置的、经过安全基线验证的 Argon2id 参数。
 *        它会自动处理内部的全局胡椒，用户无需也无法干预此过程。
 * @param derived_key (输出) 存储派生密钥的缓冲区。
 * @param derived_key_len 期望派生的密钥长度。
 * @param password 用户提供的密码字符串。
 * @param salt 一个唯一的、针对此密码的盐值 (建议使用 hsc_random_bytes 生成，
 *             长度至少为 crypto_pwhash_SALTBYTES)。
 * @return 成功返回 HSC_OK，失败返回相应的错误码。
 */
int hsc_derive_key_from_password(unsigned char* derived_key, size_t derived_key_len,
                                   const char* password, const unsigned char* salt);

/**
 * @brief [专家级] 将一个Ed25519公钥 (用于签名) 转换为X25519公钥 (用于密钥交换)。
 * @param x25519_pk_out (输出) 存储转换后X25519公钥的缓冲区。
 *                      大小必须为 crypto_box_PUBLICKEYBYTES。
 * @param ed25519_pk_in (输入) 原始的Ed25519公钥。
 *                      大小必须为 crypto_sign_PUBLICKEYBYTES。
 * @return 成功返回 HSC_OK，如果转换失败则返回 HSC_ERROR_CRYPTO_OPERATION。
 */
int hsc_convert_ed25519_pk_to_x25519_pk(unsigned char* x25519_pk_out, const unsigned char* ed25519_pk_in);

/**
 * @brief [专家级] 将一个Ed25519私钥 (用于签名) 转换为X25519私钥 (用于密钥交换)。
 * @param x25519_sk_out (输出) 存储转换后X25519私钥的缓冲区。
 *                      **警告**: 此密钥为敏感数据，建议存储在安全内存中，并在用后立即擦除。
 *                      大小必须为 crypto_box_SECRETKEYBYTES。
 * @param ed25519_sk_in (输入) 原始的Ed25519私钥。
 *                      大小必须为 crypto_sign_SECRETKEYBYTES。
 * @return 成功返回 HSC_OK，如果转换失败则返回 HSC_ERROR_CRYPTO_OPERATION。
 */
int hsc_convert_ed25519_sk_to_x25519_sk(unsigned char* x25519_sk_out, const unsigned char* ed25519_sk_in);


/**
 * @brief [专家级] [分离模式] 使用AEAD (XChaCha20-Poly1305) 对称加密数据。
 *        此版本允许用户提供 Nonce，并将认证标签 (Tag) 与密文分开返回。
 * @param ciphertext (输出) 加密后的数据缓冲区 (仅包含纯密文)。
 * @param tag_out (输出) 生成的16字节认证标签。
 * @param message 要加密的明文。
 * @param message_len 明文的长度。
 * @param additional_data (可选) 附加验证数据 (AD)，如果不需要则为 NULL。
 * @param ad_len 附加数据的长度，如果 AD 为 NULL 则为 0。
 * @param nonce (输入) 24字节的Nonce。
 *              **!!! 致命安全警告 !!!**
 *              **对于同一个密钥，绝不能使用相同的Nonce加密两条不同的消息。**
 *              **重用Nonce将彻底摧毁此加密算法的安全性。**
 *              **强烈建议使用 hsc_random_bytes 为每条消息生成一个唯一的Nonce。**
 * @param key 加密密钥。
 * @return 成功返回 HSC_OK，失败返回 HSC_ERROR_CRYPTO_OPERATION。
 */
int hsc_aead_encrypt_detached(unsigned char* ciphertext, unsigned char* tag_out,
                              const unsigned char* message, size_t message_len,
                              const unsigned char* additional_data, size_t ad_len,
                              const unsigned char* nonce, const unsigned char* key);

/**
 * @brief [专家级] [分离模式] 使用AEAD (XChaCha20-Poly1305) 对称解密数据。
 * @param decrypted_message (输出) 解密后的明文缓冲区。
 * @param ciphertext 要解密的纯密文。
 * @param ciphertext_len 纯密文的长度。
 * @param tag (输入) 与密文关联的16字节认证标签。
 * @param additional_data (可选) 附加验证数据 (AD)。
 * @param ad_len 附加数据的长度。
 * @param nonce (输入) 用于加密的24字节Nonce。
 * @param key 解密密钥。
 * @return 成功返回 HSC_OK，如果认证失败或解密失败则返回 HSC_ERROR_CRYPTO_OPERATION。
 */
int hsc_aead_decrypt_detached(unsigned char* decrypted_message,
                              const unsigned char* ciphertext, size_t ciphertext_len,
                              const unsigned char* tag,
                              const unsigned char* additional_data, size_t ad_len,
                              const unsigned char* nonce, const unsigned char* key);


#endif // HSC_KERNEL_H
```

### **结论**

委员会认为，上述修订方案是在不妥协项目核心安全原则的前提下，为高级用户提供额外灵活性的最佳路径。它通过提供**受约束的、高内聚的**新API，而不是暴露原始的、低级别的内部构件，来满足您的需求。这种方法既增强了库的通用性，又保留了其作为高安全性内核的本质。

我们强烈建议您采纳此方案。