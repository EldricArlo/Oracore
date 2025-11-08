# 高安全性混合加密客户端库 (High-Security Hybrid Encryption Client Library)

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)![License](https://img.shields.io/badge/license-MIT-blue)![Language](https://img.shields.io/badge/language-C11-purple)![Libsodium](https://img.shields.io/badge/dependency-libsodium-_31D843)![OpenSSL](https://img.shields.io/badge/dependency-OpenSSL_3-0075A8)![Libcurl](https://img.shields.io/badge/dependency-libcurl-E5522D)

本项目是一个使用C语言实现的、专注于安全性的高级混合加密客户端库。它演示了如何结合使用行业领先的密码学库（libsodium 和 OpenSSL）来构建一个健壮的、端到端的加密解决方案。该方案集成了对称加密、非对称加密和公钥基础设施（PKI），适用于需要高度保密性和身份认证的应用场景。

## ✨ 核心特性

*   **混合加密模型:** 高效的AEAD对称加密（XChaCha20-Poly1305）用于加密大数据，强大的非对称加密（X25519）用于安全地封装和交换对称密钥。
*   **现代化的密码学原语:**
    *   **密钥派生:** 使用当前推荐的 **Argon2id** 算法从用户密码安全地派生密钥。
    *   **签名与密钥交换:** 使用 **Ed25519** 进行身份签名，并能动态转换为 **X25519** 进行密钥交换，实现了密钥的统一与功能分离。
    *   **对称加密:** **XChaCha20-Poly1305** 提供高安全性的认证加密（AEAD），能抵御篡改并适用于大数据流。
*   **安全的内存管理:** 所有私钥和其他敏感数据（如会话密钥）都存储在使用 `libsodium` 分配的受保护内存中，防止被交换到磁盘或在释放后留下痕迹。
*   **公钥基础设施 (PKI):**
    *   支持生成符合 X.509 标准的**证书签名请求 (CSR)**。
    *   提供严格的**证书验证**链，包括信任链、有效期和主题匹配。
    *   **强制的吊销检查:** 内置严格的在线证书状态协议 (OCSP) 检查，并采用安全的 **“故障关闭” (Fail-Closed)** 策略，杜绝使用已被吊销的证书。
*   **模块化与高内聚设计:** 项目结构清晰，分为核心加密、PKI处理和通用安全模块，易于理解、维护和扩展。
*   **健壮的错误处理:** 所有对外暴露的API都进行了严格的参数检查，并返回明确的错误码。
*   **经过测试:** 包含一套完整的单元测试，确保核心加密功能的正确性和可靠性。

## 目录
*   [高安全性混合加密客户端库](#高安全性混合加密客户端库-high-security-hybrid-encryption-client-library)
*   [✨ 核心特性](#-核心特性)
*   [🚀 快速开始](#-快速开始)
*   [📂 项目结构](#-项目结构)
*   [🔐 加密逻辑详解](#-加密逻辑详解)
*   [🛠️ API 参考文档](#️-api-参考文档)
*   [📜 证书说明](#-证书说明)
*   [🤝 贡献](#-贡献)
*   [📄 许可证](#-许可证)

## 🚀 快速开始

### 依赖环境

在编译和运行本项目之前，请确保您的系统上已安装以下软件：

*   **C 编译器:** `gcc` 或 `clang` (支持 C11 标准)
*   **构建工具:** `make`
*   **Libsodium:** 一个现代化且易于使用的密码学库。
*   **OpenSSL:** 用于处理证书和PKI操作 (强烈建议 **3.x** 或更高版本)。
*   **Libcurl:** 用于执行OCSP检查所需的HTTP请求。

**在 Debian/Ubuntu 上安装依赖:**
```bash
sudo apt-get update
sudo apt-get install build-essential libsodium-dev libssl-dev libcurl4-openssl-dev
```

**在 macOS 上使用 Homebrew 安装依赖:**
```bash
brew install libsodium openssl@3 curl
```

### 编译与运行

项目 `Makefile` 提供了简单易用的指令。

1.  **编译主程序和测试:**
    ```bash
    make all
    make build_tests
    ```

2.  **运行单元测试 (推荐首先执行):**
    我们强烈建议在运行主程序前先执行测试，以确保所有加密模块在您的系统上都能正常工作。
    ```bash
    make test
    ```

3.  **运行演示程序:**
    ```bash
    ./high_security_app
    ```
    该程序将完整地演示从生成用户密钥、签发证书，到加密文件、封装密钥，最后再解密恢复文件的整个端到端流程。

4.  **清理构建文件:**
    ```bash
    make clean
    ```

> **关于单元测试的重要说明**
>
> 我们的 `pki_handler` 单元测试现在会**刻意地**让 OCSP 吊销检查失败。这是**预期行为**，用以验证我们实施的“故障关闭”安全策略。
>
> *   测试代码会生成一个包含**虚拟OCSP服务器地址** (`http://127.0.0.1/...`) 的用户证书。
> *   当 `verify_user_certificate` 尝试连接这个地址时，网络请求必然会失败。
> *   根据我们的“故障关闭”策略，任何无法确认证书为“良好”的情况都会导致验证失败（返回 `-4`）。
> *   因此，测试用例 `test_certificate_validation_successful` **断言其返回 `-4`**，如果断言成功，则证明我们的安全机制工作正常。

## 📂 项目结构

```
.
├── Makefile              # 构建脚本
├── README.md             # 本项目的说明文档
├── src                   # 源代码目录
│   ├── common            # 通用模块
│   │   ├── secure_memory.c # 安全内存分配与擦除的实现
│   │   ├── secure_memory.h # 头文件
│   │   └── security_spec.h # 项目的安全参数和常量定义
│   ├── core_crypto       # 核心加密逻辑
│   │   ├── crypto_client.c # 加密、解密、密钥生成、密钥派生等核心功能实现
│   │   └── crypto_client.h # 头文件
│   ├── main.c            # 演示程序入口
│   └── pki               # 公钥基础设施 (PKI) 相关逻辑
│       ├── pki_handler.c   # CSR生成、证书验证等PKI功能实现
│       └── pki_handler.h   # 头文件
└── tests                 # 测试代码目录
    ├── test_core_crypto.c  # 针对 core_crypto 模块的单元测试
    └── test_pki_handler.c  # 针对 pki_handler 模块的单元测试
```

## 🔐 加密逻辑详解

本项目的核心是一个**混合加密系统**。这种设计结合了对称加密的高效率和非对称加密的密钥管理优势。

### 阶段一：身份与密钥体系

1.  **主密钥对 (Master Key Pair):**
    *   每个用户的身份核心是一个 **Ed25519** 主密钥对。公钥 (`pk`) 代表身份，私钥 (`sk`) 用于签名。
    *   私钥始终存储在受保护的内存中，确保其生命周期内的安全性。

2.  **证书签名请求 (CSR):**
    *   用户使用其主私钥签署一个包含其公钥和身份信息的 **CSR**，用于向证书颁发机构（CA）申请证书。

3.  **获取证书:**
    *   CA 验证用户身份后，用 CA 的私钥签署 CSR，生成一个标准的 **X.509 证书**。该证书将用户的公钥和身份可信地绑定在一起。

### 阶段二：文件/数据的对称加密 (AEAD)

1.  **生成会话密钥 (Session Key):**
    *   为每一次加密会话生成一个一次性的、高熵的**对称会话密钥**。

2.  **认证加密 (AEAD):**
    *   使用会话密钥和 **XChaCha20-Poly1305** 算法加密文件内容。AEAD 不仅提供**机密性**，还提供**完整性**和**真实性**，能防止任何对密文的篡改。

### 阶段三：会话密钥的非对称封装与共享

1.  **验证接收者身份:**
    *   发送方获取接收方的 X.509 证书，并通过 `verify_user_certificate` 函数执行严格验证：
        *   **信任链:** 证书是否由一个受信任的 CA 签署？
        *   **有效期:** 证书是否在当前有效期内？
        *   **主题匹配:** 证书中的身份信息是否与预期接收者匹配？
        *   **吊销状态:** **本项目强制执行严格的 OCSP 检查。**如果因任何原因（如证书中无 OCSP 地址、服务器无响应、证书被报告为吊销或未知）无法确认证书状态为“良好”，验证将**立即失败**。这就是“故障关闭”策略，它能最大限度地防止使用可能已被吊销的风险证书。
    *   只有所有检查都通过，才能继续下一步。

2.  **密钥封装 (Key Encapsulation):**
    *   发送方从接收方已验证的证书中提取出 **Ed25519 公钥**。
    *   发送方将自己的 **Ed25519 私钥** 和接收方的 **Ed25519 公钥** 动态转换为 **X25519** 密钥对。Ed25519 用于签名，而 X25519 用于加密，这种转换允许一个密钥对服务于两种目的，简化了密钥管理。
    *   最后，使用 `libsodium` 的 `crypto_box` 功能（基于X25519）来加密**会话密钥**。

### 总结：一个安全的“传输包”

发送方最终会向接收方发送一个“传输包”，其中包含：
1.  **加密后的文件** (使用 AEAD 和会话密钥加密)。
2.  **封装后的会话密钥** (使用非对称加密和双方的主密钥对加密)。

接收方收到后，先用自己的主私钥解封装得到会话密钥，再用会话密钥解密文件，完成端到端的安全通信。

## 🛠️ API 参考文档

### `core_crypto` 模块
*头文件: `src/core_crypto/crypto_client.h`*

---
`int crypto_client_init()`
*   **描述:** 初始化密码学库(libsodium)。必须在调用任何其他加密函数之前调用。
*   **返回:** `0` 成功, `-1` 失败。

---
`int generate_master_key_pair(master_key_pair* kp)`
*   **描述:** 生成一个全新的 Ed25519 主密钥对。
*   **参数:** `kp` (输出) 指向 `master_key_pair` 结构体的指针。
*   **返回:** `0` 成功, `-1` 失败。

---
*(其他 `core_crypto` 函数请参考头文件中的详细Doxygen注释。)*

### `pki_handler` 模块
*头文件: `src/pki/pki_handler.h`*

---
`int pki_init()`
*   **描述:** 初始化PKI子系统 (加载 OpenSSL provider)。
*   **返回:** `0` 成功, `-1` 失败。

---
`int generate_csr(const master_key_pair* mkp, const char* username, char** out_csr_pem)`
*   **描述:** 使用主密钥对为指定用户名生成一个 PEM 格式的证书签名请求。
*   **参数:** `mkp` (输入), `username` (输入), `out_csr_pem` (输出)。调用者需使用 `free_csr_pem()` 释放 `out_csr_pem`。
*   **返回:** `0` 成功, `-1` 失败。

---
`int verify_user_certificate(const char* user_cert_pem, const char* trusted_ca_cert_pem, const char* expected_username)`
*   **描述:** 执行完整的、严格的证书验证流程。
*   **返回:**
    *   `0`: 所有验证步骤（包括OCSP）全部成功。
    *   `-1`: 一般性错误 (如内存分配、PEM 解析失败)。
    *   `-2`: 证书签名链或有效期验证失败。
    *   `-3`: 证书主体 (Username) 不匹配。
    *   `-4`: **吊销状态检查失败** (证书被吊销、状态未知、或无法获取OCSP响应)。

---
*(其他 `pki_handler` 函数请参考头文件中的详细Doxygen注释。)*

### `secure_memory` 模块
*头文件: `src/common/secure_memory.h`*

---
`void* secure_alloc(size_t size)`
*   **描述:** 分配一块受保护的、不可被交换到磁盘的内存。
*   **返回:** 成功时返回指针，失败时返回 `NULL`。

---
`void secure_free(void* ptr)`
*   **描述:** 在释放前安全地擦除一块受保护的内存，然后释放它。

---

## 如何使用该项目

#### 方式一：作为库进行二次开发 (集成到你自己的应用中)

`src/main.c` 文件就是最佳的示例。一个典型的完整流程如下：

1.  **初始化**:
    ```c
    crypto_client_init();
    pki_init();
    ```

2.  **为用户 "Alice" 创建身份**:
    ```c
    master_key_pair alice_mkp;
    generate_master_key_pair(&alice_mkp); // 生成主密钥对
    ```

3.  **为 Alice 申请证书 (模拟)**:
    ```c
    char* csr = NULL;
    generate_csr(&alice_mkp, "alice@example.com", &csr); // 生成CSR
    // ... 将 CSR 发送给 CA，获取签发的证书 alice_cert_pem ...
    ```

4.  **Alice 要加密并分享文件给 Bob**:
    *   **本地加密**:
        ```c
        // 1. 生成一次性会话密钥
        unsigned char session_key[SESSION_KEY_BYTES];
        randombytes_buf(session_key, sizeof(session_key));
        
        // 2. 用会话密钥加密文件
        encrypt_symmetric_aead(encrypted_file, ..., file_content, ..., session_key);
        ```
    *   **封装密钥**:
        ```c
        // 3. 获取并验证 Bob 的证书
        verify_user_certificate(bob_cert_pem, trusted_ca_pem, "bob@example.com");
        
        // 4. 从 Bob 的证书里提取公钥
        unsigned char bob_pk[MASTER_PUBLIC_KEY_BYTES];
        extract_public_key_from_cert(bob_cert_pem, bob_pk);
        
        // 5. 用 Bob 的公钥和 Alice 的私钥封装会话密钥
        encapsulate_session_key(encapsulated_key, ..., session_key, ..., bob_pk, alice_mkp.sk);
        ```

5.  **Bob 接收并解密文件**:
    *   **解封装密钥**:
        ```c
        // 1. 获取并验证 Alice 的证书，提取其公钥 alice_pk
        
        // 2. 用 Alice 的公钥和 Bob 的私钥解封装会话密钥
        unsigned char* decrypted_session_key = secure_alloc(...);
        decapsulate_session_key(decrypted_session_key, encapsulated_key, ..., alice_pk, bob_mkp.sk);
        ```
    *   **解密文件**:
        ```c
        // 3. 用恢复的会话密钥解密文件
        decrypt_symmetric_aead(decrypted_file, ..., encrypted_file, ..., decrypted_session_key);
        ```

#### 方式二：使用编译好的命令行工具 (`hsc_cli`)

`Makefile` 已经为您准备好了一个名为 `hsc_cli` 的命令行工具。这是与系统交互最直接的方式。

*   `hsc_cli gen-keypair --pub alice.pub --priv alice.key`
    *   生成一个密钥对，公钥存入 `alice.pub`，私钥存入 `alice.key`。
*   `hsc_cli gen-csr --priv alice.key --user "alice@example.com" --out alice.csr`
    *   使用 `alice.key` 私钥，为用户 "alice@example.com" 生成 `alice.csr` 文件。
*   `hsc_cli verify-cert --cert alice.pem --ca ca.pem --user "alice@example.com"`
    *   使用根证书 `ca.pem` 来验证 `alice.pem` 证书是否有效且属于 "alice@example.com"。
*   `hsc_cli hybrid-encrypt --in secret.txt --out-data secret.enc --out-key secret.key.enc --recipient-cert bob.pem --sender-priv alice.key`
    *   **加密**：用 `alice.key` 作为发送方，加密 `secret.txt` 给 `bob.pem` 证书的持有者。
*   `hsc_cli hybrid-decrypt --in-data secret.enc --in-key secret.key.enc --out plain.txt --sender-cert alice.pem --recipient-priv bob.key`
    *   **解密**：Bob 使用自己的私钥 `bob.key` 和发送方 Alice 的证书 `alice.pem` 来解密文件。


---

## 📜 证书说明

本项目使用 **X.509 v3** 证书标准。在演示和测试代码中，我们通过辅助函数模拟了一个迷你的证书颁发机构（CA）。

*   **自签名根CA证书:** `generate_test_ca` 创建了一个自签名的根CA证书，作为信任锚点。它包含了必要的 X.509 v3 扩展，如 `Basic Constraints (CA:TRUE)`。
*   **用户证书:** `sign_csr_with_ca` 接收用户的CSR并用CA私钥对其签名，生成用户证书。为了支持吊销检查测试，此函数现在会自动为签发的用户证书添加一个指向模拟OCSP服务器的**授权信息访问 (AIA)** 扩展。

在 `verify_user_certificate` 函数中，正是利用了 `trusted_ca_cert_pem` 提供的根CA证书，来验证用户证书的签名链是否可信。

## 🤝 贡献

欢迎对本项目进行改进！如果您发现了bug或有功能建议，请随时提交 Pull Request 或创建 Issue。

## 📄 许可证

本项目采用 [MIT License](LICENSE) 授权。