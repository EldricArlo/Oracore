#### 1. 初始化与全局管理

这些函数负责库的生命周期管理，必须在程序开始和结束时被正确调用。

| 函数签名 | 作用 |
| :--- | :--- |
| `int hsc_init()` | **（必须最先调用）** 初始化整个内核库。它会执行所有必要的底层初始化操作，包括 `libsodium` 的初始化（确保选择最优算法并线程安全）、`libcurl` 的全局初始化（用于OCSP网络请求）以及 `OpenSSL` 的初始化。 |
| `void hsc_cleanup()` | **（必须最后调用）** 清理 `hsc_init()` 创建的全局资源。应在程序退出前调用，以确保干净地释放所有句柄。 |
| `void hsc_random_bytes(void* buf, size_t size)` | 生成密码学安全的随机字节。它内部调用 `libsodium` 的 `randombytes_buf`，这比C标准库的 `rand()` 要安全得多，适用于生成密钥、盐值（salt）、随机数（nonce）等。 |

---

#### 2. 主密钥对管理

这些API用于处理核心的、长期的身份密钥对（Ed25519）。

| 函数签名 | 作用 |
| :--- | :--- |
| `hsc_master_key_pair* hsc_generate_master_key_pair()` | 生成一个全新的主密钥对（公钥+私钥）。私钥会被自动分配在**受保护的安全内存**中，以防止被交换到磁盘。返回的是一个不透明指针，必须使用 `hsc_free_master_key_pair` 释放。 |
| `hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(const char* priv_key_path)` | 从文件中加载一个私钥，并从中派生出对应的公钥，组装成一个密钥对结构体。同样，加载后的私钥会存储在**安全内存**中。 |
| `int hsc_save_master_key_pair(const hsc_master_key_pair* kp, const char* pub_key_path, const char* priv_key_path)` | 将一个密钥对分别保存到两个文件：一个公钥文件和一个私钥文件。 |
| `void hsc_free_master_key_pair(hsc_master_key_pair** kp)` | **（必须调用）** 安全地释放一个主密钥对。它会**先擦除私钥所在的安全内存**，然后再释放结构体本身，防止敏感信息残留在内存中。 |

---

#### 3. PKI 与证书管理

这组API处理与公钥基础设施（Public Key Infrastructure）相关的所有操作，是建立信任链的核心。

| 函数签名 | 作用 |
| :--- | :--- |
| `int hsc_generate_csr(const hsc_master_key_pair* mkp, const char* username, char** out_csr_pem)` | 使用给定的主密钥对和用户名，生成一个PEM格式的证书签名请求（CSR）。调用者需要将这个CSR提交给证书颁发机构（CA）进行签名，以获得正式的X.509证书。函数会为 `out_csr_pem` 分配内存，必须使用 `hsc_free_pem_string` 释放。 |
| `void hsc_free_pem_string(char* pem_string)` | 释放由 `hsc_generate_csr` 分配的PEM字符串内存。 |
| `int hsc_verify_user_certificate(const char* user_cert_pem, const char* trusted_ca_cert_pem, const char* expected_username)` | **（核心安全函数）** 对一个用户证书执行完整的、严格的验证。这个函数会检查以下所有内容：<br>1. **签名链**：用户证书是否由受信任的CA证书签署。<br>2. **有效期**：证书是否在当前有效期内。<br>3. **主体匹配**：证书的通用名称（Common Name）是否与预期的用户名匹配。<br>4. **吊销状态**：通过OCSP**强制检查**证书是否已被吊销。如果OCSP检查失败（如网络不通），验证也会失败（**故障关闭策略**）。 |
| `int hsc_extract_public_key_from_cert(const char* user_cert_pem, unsigned char* public_key_out)` | 从一个**已经通过验证**的证书中，提取出原始的、32字节的Ed25519公钥。这是在与其他用户通信前，获取其可信公钥的标准方式。 |

---

#### 4. 密钥封装（非对称加解密）

这组API用于混合加密中的关键一步：安全地交换对称会话密钥。

| 函数签名 | 作用 |
| :--- | :--- |
| `int hsc_encapsulate_session_key(...)` | **（非对称加密）** 封装（或称“包装”）一个会话密钥。它使用接收者的公钥和发送者自己的私钥，通过X25519对一个短暂的会话密钥进行加密。只有指定的接收者才能解开它。 |
| `int hsc_decapsulate_session_key(...)` | **（非对称解密）** 解封装一个会话密钥。接收者使用发送者的公钥和自己的私钥来解密被封装的会话密钥，以恢复原始的会话密钥明文。 |

---

#### 5. 单次对称加解密 (AEAD)

适用于对较小、独立的、单块数据进行加密。

| 函数签名 | 作用 |
| :--- | :--- |
| `int hsc_aead_encrypt(...)` | 使用给定的对称密钥（如通过解封装恢复的会话密钥），对一段消息进行**认证加密（AEAD）**。输出的密文不仅包含加密的数据，还包含了认证标签，可以防止数据被篡改。 |
| `int hsc_aead_decrypt(...)` | 解密并验证由 `hsc_aead_encrypt` 生成的密文。如果密文在传输过程中被任何方式篡改，解密会失败。 |

---

#### 6. 流式对称加解密

这组API专为大文件设计，可以分块处理数据，内存占用低。

| 函数签名 | 作用 |
| :--- | :--- |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(...)` | 创建并初始化一个**加密流**。它会生成一个流头部（header），这个头部需要被保存并与加密数据一同发送给接收方。 |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(...)` | 使用接收到的流头部，创建并初始化一个**解密流**。 |
| `void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state)` | 安全地释放加密或解密流的状态对象。 |
| `int hsc_crypto_stream_push(...)` | 加密数据流中的一个数据块（chunk）。可以循环调用此函数来处理整个大文件。最后一个数据块需要使用特殊的 `HSC_STREAM_TAG_FINAL` 标签。 |
| `int hsc_crypto_stream_pull(...)` | 解密数据流中的一个数据块。它同样会验证每个数据块的完整性，如果任何数据块被篡改，函数会失败。 |

---

#### 7. 安全内存管理

直接向库的使用者暴露 `libsodium` 的安全内存功能，这是一个非常贴心且重要的特性。

| 函数签名 | 作用 |
| :--- | :--- |
| `void* hsc_secure_alloc(size_t size)` | 分配一块受保护的、不可被操作系统交换到磁盘的内存。**强烈推荐**用它来存储任何敏感的明文数据，如解密后的会话密钥或文件内容。 |
| `void hsc_secure_free(void* ptr)` | 安全地释放由 `hsc_secure_alloc` 分配的内存。它会在释放前用零**彻底擦除这块内存**。 |



#### 1. Initialization & Global Management

These functions manage the library's lifecycle and must be called correctly at the beginning and end of your program.

| Function Signature | Purpose |
| :--- | :--- |
| `int hsc_init()` | **(Must be called first)** Initializes the entire core library. It performs all necessary low-level initialization, including initializing `libsodium` (ensuring optimal algorithms are selected and that it's thread-safe), `libcurl` globally (for OCSP network requests), and `OpenSSL`. |
| `void hsc_cleanup()` | **(Must be called last)** Cleans up the global resources created by `hsc_init()`. It should be called before the program exits to ensure all handles are released cleanly. |
| `void hsc_random_bytes(void* buf, size_t size)` | Generates cryptographically secure random bytes. Internally, it calls `libsodium`'s `randombytes_buf`, which is significantly more secure than the standard C library's `rand()`. It's suitable for generating keys, salts, nonces, etc. |

---

#### 2. Master Key Pair Management

These APIs are used to handle the core, long-term identity key pairs (Ed25519).

| Function Signature | Purpose |
| :--- | :--- |
| `hsc_master_key_pair* hsc_generate_master_key_pair()` | Generates a brand new master key pair (public + private key). The private key is automatically allocated in **protected secure memory** to prevent it from being swapped to disk. It returns an opaque pointer that must be freed using `hsc_free_master_key_pair`. |
| `hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(const char* priv_key_path)` | Loads a private key from a file, derives the corresponding public key, and assembles them into a key pair structure. The loaded private key is also stored in **secure memory**. |
| `int hsc_save_master_key_pair(const hsc_master_key_pair* kp, const char* pub_key_path, const char* priv_key_path)` | Saves a key pair to two separate files: one for the public key and one for the private key. |
| `void hsc_free_master_key_pair(hsc_master_key_pair** kp)` | **(Must be called)** Securely frees a master key pair. It **first wipes the secure memory holding the private key** before freeing the structure itself, preventing sensitive information from lingering in memory. |

---

#### 3. PKI & Certificate Management

This set of APIs handles all operations related to Public Key Infrastructure (PKI) and is central to establishing a chain of trust.

| Function Signature | Purpose |
| :--- | :--- |
| `int hsc_generate_csr(const hsc_master_key_pair* mkp, const char* username, char** out_csr_pem)` | Generates a PEM-formatted Certificate Signing Request (CSR) using the given master key pair and username. The caller needs to submit this CSR to a Certificate Authority (CA) to be signed, in order to obtain a formal X.509 certificate. The function allocates memory for `out_csr_pem`, which must be freed using `hsc_free_pem_string`. |
| `void hsc_free_pem_string(char* pem_string)` | Frees the memory allocated for the PEM string by `hsc_generate_csr`. |
| `int hsc_verify_user_certificate(const char* user_cert_pem, const char* trusted_ca_cert_pem, const char* expected_username)` | **(Core security function)** Performs a complete and strict validation of a user certificate. This function checks all of the following:<br>1. **Signature Chain**: Whether the user certificate was signed by the trusted CA certificate.<br>2. **Validity Period**: Whether the certificate is currently within its validity period.<br>3. **Subject Match**: Whether the certificate's Common Name (CN) matches the expected username.<br>4. **Revocation Status**: **Strictly checks** if the certificate has been revoked via OCSP. If the OCSP check fails (e.g., due to a network issue), the validation will also fail (a **fail-closed** policy). |
| `int hsc_extract_public_key_from_cert(const char* user_cert_pem, unsigned char* public_key_out)` | Extracts the raw, 32-byte Ed25519 public key from a certificate that has **already been verified**. This is the standard way to obtain a trusted public key before communicating with another user. |

---

#### 4. Key Encapsulation (Asymmetric Encryption)

This set of APIs is used for a critical step in hybrid encryption: securely exchanging a symmetric session key.

| Function Signature | Purpose |
| :--- | :--- |
| `int hsc_encapsulate_session_key(...)` | **(Asymmetric Encryption)** Encapsulates (or "wraps") a session key. It uses the recipient's public key and the sender's private key to encrypt an ephemeral session key with X25519. Only the intended recipient can decrypt it. |
| `int hsc_decapsulate_session_key(...)` | **(Asymmetric Decryption)** Decapsulates a session key. The recipient uses the sender's public key and their own private key to decrypt the encapsulated session key, recovering the original plaintext session key. |

---

#### 5. Single-Part AEAD Symmetric Encryption

Suitable for encrypting smaller, independent, single blocks of data.

| Function Signature | Purpose |
| :--- | :--- |
| `int hsc_aead_encrypt(...)` | Encrypts a piece of data using **Authenticated Encryption with Associated Data (AEAD)** with a given symmetric key (such as a session key recovered via decapsulation). The output ciphertext includes not only the encrypted data but also an authentication tag to prevent tampering. |
| `int hsc_aead_decrypt(...)` | Decrypts and verifies ciphertext generated by `hsc_aead_encrypt`. If the ciphertext has been tampered with in any way during transit, decryption will fail. |

---

#### 6. Streaming Symmetric Encryption

This set of APIs is designed specifically for large files, allowing data to be processed in chunks with a low memory footprint.

| Function Signature | Purpose |
| :--- | :--- |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(...)` | Creates and initializes an **encryption stream**. It generates a stream header, which needs to be saved and sent to the recipient along with the encrypted data. |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(...)` | Creates and initializes a **decryption stream** using the received stream header. |
| `void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state)` | Securely frees the state object for an encryption or decryption stream. |
| `int hsc_crypto_stream_push(...)` | Encrypts a chunk of data in the stream. This function can be called in a loop to process an entire large file. The final chunk requires the special `HSC_STREAM_TAG_FINAL` tag. |
| `int hsc_crypto_stream_pull(...)` | Decrypts a chunk of data from the stream. It also verifies the integrity of each chunk; if any chunk has been tampered with, the function will fail. |

---

#### 7. Secure Memory Management

Exposes `libsodium`'s secure memory functions directly to the library user, which is a highly convenient and important feature.

| Function Signature | Purpose |
| :--- | :--- |
| `void* hsc_secure_alloc(size_t size)` | Allocates a block of protected memory that cannot be swapped to disk by the OS. It is **strongly recommended** for storing any sensitive plaintext data, such as decrypted session keys or file contents. |
| `void hsc_secure_free(void* ptr)` | Securely frees memory allocated by `hsc_secure_alloc`. Before freeing, it **thoroughly wipes the memory** with zeros. |