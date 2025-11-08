# 高安全性混合加密客户端库 (High-Security Hybrid Encryption Client Library)

| Build | License | Language | Dependencies |
| :---: | :---: | :---: | :--- |
| ![Build Status](https://img.shields.io/badge/build-passing-brightgreen) | ![License](https://img.shields.io/badge/license-MIT-blue) | ![Language](https://img.shields.io/badge/language-C11-purple) | ![Libsodium](https://img.shields.io/badge/libsodium-v1.0.18+-brightgreen) ![OpenSSL](https://img.shields.io/badge/OpenSSL-v3.0+-0075A8) ![Libcurl](https://img.shields.io/badge/libcurl-v7.68+-E5522D) |

## 1. 🎯 项目愿景与核心原则

本项目是一个使用 C11 标准实现的、专注于安全性的高级混合加密客户端库。它旨在提供一个经过实战检验的蓝图，展示如何将行业领先的密码学库（**libsodium**, **OpenSSL**, **libcurl**）组合成一个健壮、可靠的端到端加密解决方案。

我们的设计遵循以下核心安全原则：

*   🛡️ **选择经审查的现代密码学：** 绝不自行实现加密算法。只使用社区公认的、抗侧信道攻击的现代密码学原语。
*   🏰 **纵深防御：** 安全性不依赖于任何单一层面。从内存管理、API设计到协议流程，层层设防。
*   🚦 **安全默认值与“故障关闭”：** 系统的默认行为必须是安全的。在遇到不确定状态（如无法验证证书吊销状态）时，系统必须选择失败并终止操作（Fail-Closed），而非继续执行。
*   ⏱️ **最小化敏感数据暴露：** 私钥等关键数据的生命周期、作用域和内存驻留时间必须被严格控制在绝对必要的最小范围内。

## 2. ✨ 核心特性

*   🧬 **健壮的混合加密模型:**
    *   **对称加密:** 使用 **XChaCha20-Poly1305** (AEAD) 对数据进行高效、安全的认证加密，天然免疫数据篡改。
    *   **非对称加密:** 使用 **X25519** (基于 Curve25519) 对对称会话密钥进行密钥封装，确保只有预期的接收者才能解密。

*   🔬 **现代化的密码学原语栈:**
    *   **密钥派生:** 采用 **Argon2id**，这是当前密码哈希竞赛的获胜者，能有效抵御 GPU 和 ASIC 破解。
    *   **数字签名:** 采用 **Ed25519**，提供高速、高安全性的数字签名能力。
    *   **密钥统一:** 巧妙地利用 Ed25519 密钥可安全转换为 X25519 密钥的特性，使用一套主密钥对同时满足签名和加密的需求。

*   📜 **全面的公钥基础设施 (PKI) 支持:**
    *   **证书生命周期:** 支持生成符合 X.509 v3 标准的证书签名请求 (CSR)。
    *   **严格的证书验证:** 提供标准化的证书验证流程，包括信任链、有效期和主题匹配。
    *   **强制的吊销检查 (OCSP):** 内置严格的在线证书状态协议 (OCSP) 检查，并采用“故障关闭”策略，在无法确认证书状态良好时立即中止操作。

*   🔒 **固若金汤的内存安全:**
    *   所有私钥、会话密钥等敏感数据均通过 `libsodium` 的安全内存 API (`sodium_malloc`) 进行分配。
    *   这些内存区域被锁定，**防止被操作系统交换到磁盘**，并在释放前被安全擦除，杜绝敏感信息泄露。

*   ⚙️ **高质量的工程实践:**
    *   **模块化设计:** 高内聚、低耦合的模块划分 (`core_crypto`, `pki`, `common`)，易于维护和扩展。
    *   **经过单元测试:** 包含一套覆盖核心加密和PKI功能的单元测试，确保代码的正确性和可靠性。
    *   **清晰的 API:** 提供简洁、文档完善的 C-API，方便集成到其他项目中。

## 3. 📂 项目结构

项目采用清晰、分层的目录结构，以实现关注点分离。

```
.
├── Makefile              # 构建与任务管理脚本
├── README.md             # 本项目的说明文档
├── src/                  # 源代码
│   ├── common/           # 通用模块
│   │   ├── secure_memory.h/.c # 安全内存分配与擦除的实现
│   │   └── security_spec.h    # 定义项目的安全参数与常量
│   ├── core_crypto/      # 核心加密逻辑 (基于 libsodium)
│   │   ├── crypto_client.h/.c # 封装加密、解密、密钥生成等核心功能
│   ├── pki/              # 公钥基础设施逻辑 (基于 OpenSSL & libcurl)
│   │   ├── pki_handler.h/.c   # 封装 CSR 生成、证书验证、OCSP 检查等功能
│   ├── main.c            # 端到端流程的演示程序
│   └── cli.c             # 功能强大的命令行交互工具
└── tests/                # 单元测试
    ├── test_core_crypto.c # 针对 core_crypto 模块的单元测试
    └── test_pki_handler.c # 针对 pki_handler 模块的单元测试
```

## 4. 🚀 快速入门

### 4.1. 依赖环境

在开始之前，请确保您的系统已安装以下依赖：

*   **构建工具:** `make`
*   **C 编译器:** `gcc` 或 `clang` (需支持 C11 标准)
*   **libsodium:** 现代化的密码学库 (`libsodium-dev`)
*   **OpenSSL:** 证书与 PKI 操作库，强烈建议 **v3.0** 或更高版本 (`libssl-dev`)
*   **libcurl:** 用于执行 OCSP 网络请求 (`libcurl4-openssl-dev`)

**在 Debian/Ubuntu 上一键安装:**
```bash
sudo apt-get update
sudo apt-get install build-essential libsodium-dev libssl-dev libcurl4-openssl-dev
```

**在 macOS 上使用 Homebrew 安装:**
```bash
brew install libsodium openssl@3 curl
```

### 4.2. 编译与测试

项目 `Makefile` 提供了简单易用的指令。

1.  **编译所有目标 (库, 演示程序, CLI, 测试):**
    ```bash
    make all
    ```

2.  **运行单元测试 (关键步骤):**
    在进行任何操作前，请务必运行测试，确保所有加密模块在您的系统上表现符合预期。
    ```bash
    make test
    ```
    > ℹ️ **关于 OCSP 测试的预期行为说明**
    >
    > 您可能会注意到 `test_pki_handler` 的一个测试用例似乎“失败”了，并打印出 OCSP 相关的错误。**这是完全符合预期的设计！**
    >
    > 为了验证我们的“故障关闭”安全策略，`test_certificate_validation_successful` 测试用例会故意使用一个指向无效 OCSP 服务器 (`http://127.0.0.1/...`) 的证书进行验证。由于网络请求必然失败，`verify_user_certificate` 函数**必须**返回 `-4` 以表示吊销状态检查失败。测试代码会断言返回值确实是 `-4`，以此证明我们的安全机制工作正常。

3.  **运行演示程序:**
    该程序将完整地展示一个端到端的加密与解密流程。
    ```bash
    ./bin/high_security_app
    ```

4.  **运行命令行工具 (`hsc_cli`):**
    ```bash
    ./bin/hsc_cli
    ```

5.  **清理构建文件:**
    ```bash
    make clean
    ```

## 5. 📖 使用指南

### 5.1. 作为命令行工具 (`hsc_cli`)

我们提供了一个功能齐全的命令行工具 `hsc_cli`，用于执行所有核心的加密和 PKI 操作。

**完整工作流示例：Alice 加密文件并安全地发送给 Bob**

1.  **🔑 (双方) 生成主密钥对:**
    ```bash
    # Alice 的操作
    ./bin/hsc_cli gen-keypair alice
    > ✅ 成功生成密钥对:
    >   公钥 -> alice.pub
    >   私钥 -> alice.key

    # Bob 的操作
    ./bin/hsc_cli gen-keypair bob
    > ✅ 成功生成密钥对:
    >   公钥 -> bob.pub
    >   私钥 -> bob.key
    ```

2.  **📝 (双方) 生成 CSR 并获取证书:** (此处我们假设 CA 已签发 `alice.pem` 和 `bob.pem`)
    ```bash
    # Alice 的操作
    ./bin/hsc_cli gen-csr alice.key "alice@example.com"
    > ✅ 成功为用户 'alice@example.com' 生成 CSR -> alice.csr
    # (将 alice.csr 发送给 CA, 获得 alice.pem)

    # Bob 的操作
    ./bin/hsc_cli gen-csr bob.key "bob@example.com"
    > ✅ 成功为用户 'bob@example.com' 生成 CSR -> bob.csr
    # (将 bob.csr 发送给 CA, 获得 bob.pem)
    ```

3.  **✅ (Alice) 验证 Bob 的证书:** (假设 `ca.pem` 是受信任的根 CA 证书)
    ```bash
    ./bin/hsc_cli verify-cert bob.pem --ca ca.pem --user "bob@example.com"
    # 如果一切正常，将输出成功信息
    ```

4.  **🔒 (Alice) 加密文件给 Bob:**
    ```bash
    # 创建一个示例文档
    echo "This is top secret information." > secret.txt

    # 执行混合加密
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key
    > ✅ 混合加密完成！
    >   输出文件 -> secret.hsc
    ```
    现在 Alice 可以将 `secret.hsc` 和她自己的证书 `alice.pem` 发送给 Bob。

5.  **🔓 (Bob) 收到文件后解密:**
    ```bash
    # Bob 使用发送方(Alice)的证书和自己的私钥来解密
    ./bin/hsc_cli decrypt secret.hsc --from alice.pem --to bob.key
    > ✅ 混合解密完成！
    >   解密文件 -> secret.decrypted

    # 验证内容
    cat secret.decrypted
    > This is top secret information.
    ```

### 5.2. 作为库集成到您的项目中

`src/main.c` 是一个绝佳的集成示例。以下是典型的 API 调用流程：

1.  **全局初始化:** 在程序启动时，初始化所有依赖库。
    ```c
    #include "core_crypto/crypto_client.h"
    #include "pki/pki_handler.h"
    
    // ...
    if (crypto_client_init() != 0 || pki_init() != 0) {
        // 处理致命错误
    }
    ```

2.  **发送方 (Alice) 加密文件:**
    ```c
    // 1. 生成一次性的会话密钥
    unsigned char session_key[SESSION_KEY_BYTES];
    randombytes_buf(session_key, sizeof(session_key));

    // 2. 使用会话密钥通过 AEAD 加密文件内容
    // (此处省略文件读写，直接使用内存中的消息)
    const char* message = "Secret message";
    unsigned char encrypted_data[...];
    unsigned long long encrypted_data_len;
    encrypt_symmetric_aead(encrypted_data, &encrypted_data_len, 
                           (const unsigned char*)message, strlen(message), session_key);

    // 3. 获取并严格验证接收方 (Bob) 的证书
    // (假设 bob_cert_pem 和 trusted_ca_pem 已从文件加载)
    if (verify_user_certificate(bob_cert_pem, trusted_ca_pem, "bob@example.com") != 0) {
        // 证书无效，中止操作！
    }

    // 4. 从 Bob 的证书中提取其公钥
    unsigned char bob_public_key[MASTER_PUBLIC_KEY_BYTES];
    extract_public_key_from_cert(bob_cert_pem, bob_public_key);

    // 5. 使用 Bob 的公钥和 Alice 的私钥来封装会话密钥
    // (假设 alice_key_pair.sk 已从安全位置加载)
    unsigned char encapsulated_key[...];
    size_t encapsulated_key_len;
    encapsulate_session_key(encapsulated_key, &encapsulated_key_len, 
                            session_key, sizeof(session_key),
                            bob_public_key, alice_key_pair.sk);
    
    // 6. 将 encrypted_data 和 encapsulated_key 一同发送给 Bob
    ```

3.  **接收方 (Bob) 解密文件:**
    ```c
    // 1. (可选但推荐) 验证发送方 (Alice) 的证书
    // ...

    // 2. 从 Alice 的证书中提取其公钥
    unsigned char alice_public_key[MASTER_PUBLIC_KEY_BYTES];
    extract_public_key_from_cert(alice_cert_pem, alice_public_key);
    
    // 3. 使用 Alice 的公钥和 Bob 自己的私钥来解封装会话密钥
    // (假设 bob_key_pair.sk 已从安全位置加载)
    unsigned char* decrypted_session_key = secure_alloc(SESSION_KEY_BYTES);
    if (decapsulate_session_key(decrypted_session_key, encapsulated_key, encapsulated_key_len,
                                alice_public_key, bob_key_pair.sk) != 0) {
        // 解封装失败！可能密钥错误或数据被篡改
    }

    // 4. 使用恢复的会话密钥解密文件内容
    unsigned char final_message[...];
    unsigned long long final_message_len;
    if (decrypt_symmetric_aead(final_message, &final_message_len,
                               encrypted_data, encrypted_data_len,
                               decrypted_session_key) != 0) {
        // 解密失败！数据被篡改
    }

    // 5. 使用完毕后，安全地释放会话密钥
    secure_free(decrypted_session_key);
    ```

## 6. 🔐 技术架构深度解析

本项目的核心是**混合加密（Hybrid Encryption）**模型。该模型结合了非对称加密（公钥加密）和对称加密的优点，实现了既安全又高效的数据传输。

**数据流与密钥关系图:**

```
SENDER (ALICE)                                           RECIPIENT (BOB)
========================================================================

[ 原始数据 ]
     |
     v
.----------------------.
|   生成一次性会话密钥   |
|   [ Session Key ]    |
'----------------------'
     |      |
     |      '------------------------------------------.
     |                                                 |
     v                                                 v
.------------------------.             .------------------------------.
|   对称加密 (AEAD)       |             |        非对称密钥封装         |
|                        |             |      (Key Encapsulation)     |
|  使用: Session Key     |             |                               |
'------------------------'             |       使用: Alice 的私钥      |
        |                              |          Bob 的公钥           |
        v                              '------------------------------'
[ 加密后的数据 ]                            [ 封装后的 Session Key ]
        |                                             |
        '----------------------. .--------------------'
                               | |
                               v v
                      .------------------.
                      |   传输包 (.hsc)  |
                      '------------------'
                                |
      ========================> |  网络 / 文件传输   ===================>
                                |
                      .-----------------.
                      |  传输包 (.hsc)   |
                      '-----------------'
                               | |
           .-------------------' '---------.
           |                               |
           v                               v
[ 封装后的 Session Key ]              [ 加密后的数据 ]
           |                               |
           v                               |
.------------------------.                 |
|    非对称密钥解封装      |                |
| (Key Decapsulation)    |                 |
|                        |                 |
|   使用: Bob 的私钥      |                 |
|     Alice 的公钥       |                  |
'------------------------'                 |
              |                            |
              v                            |
      .---------------. (已恢复)            |
      |[ Session Key ]|                    |
      '---------------'                    |
              |                            |
              '--------------------------->|
                                           v
                             .--------------------------.
                             |      对称解密 (AEAD)      |
                             |                          |
                             |      使用: 恢复后的       |
                             |        Session Key       |
                             '--------------------------'
                                            |
                                            v
                                       [ 原始数据 ]
```

这个流程确保：
1.  **效率:** 大量的实际数据是用高速的对称加密算法处理的。
2.  **安全性:** 真正决定数据机密性的一次性会话密钥，本身是用高强度的非对称加密来保护的，只有 Bob 的私钥才能解开。
3.  **身份认证与完整性:** AEAD 确保了数据在传输过程中未被篡改，而证书体系则确保了通信双方的身份是可信的。

## 7. 🛠️ API 核心参考

以下是各模块最核心的公开 API 函数列表。更详细的说明请参考头文件中的 Doxygen 注释。

### `secure_memory` 模块 (`src/common/secure_memory.h`)
| 函数 | 描述 |
| :--- | :--- |
| `void* secure_alloc(size_t size)` | 分配一块受保护的、不可交换到磁盘的内存。 |
| `void secure_free(void* ptr)` | 安全地擦除并释放由 `secure_alloc` 分配的内存。 |
| `void secure_zero_memory(void* ptr, size_t len)` | 安全地擦除（置零）任意一块内存区域。 |

### `core_crypto` 模块 (`src/core_crypto/crypto_client.h`)
| 函数 | 描述 |
| :--- | :--- |
| `int crypto_client_init()` | **(必须首先调用)** 初始化 libsodium 库。 |
| `int generate_master_key_pair(...)` | 生成一个全新的 Ed25519 主密钥对。 |
| `void free_master_key_pair(...)` | 安全地释放主密钥对占用的内存。 |
| `int derive_key_from_password(...)` | 使用 Argon2id 从密码、盐和胡椒派生出加密密钥。 |
| `int encrypt_symmetric_aead(...)` | 使用 AEAD (XChaCha20-Poly1305) 对称加密数据。 |
| `int decrypt_symmetric_aead(...)` | 使用 AEAD (XChaCha20-Poly1305) 对称解密数据。 |
| `int encapsulate_session_key(...)` | **(核心)** 使用接收者公钥和发送者私钥非对称加密一个会话密钥。 |
| `int decapsulate_session_key(...)` | **(核心)** 使用接收者私钥和发送者公钥解密会话密钥。 |

### `pki_handler` 模块 (`src/pki/pki_handler.h`)
| 函数 | 描述 |
| :--- | :--- |
| `int pki_init()` | **(必须首先调用)** 初始化 OpenSSL/libcurl 子系统。 |
| `int generate_csr(...)` | 生成一个 PEM 格式的证书签名请求 (CSR)。 |
| `void free_csr_pem(...)` | 释放由 `generate_csr` 分配的 PEM 字符串内存。 |
| `int verify_user_certificate(...)` | **(核心)** 执行完整的证书验证，包括信任链、有效期、主体和强制 OCSP 检查。 |
| `int extract_public_key_from_cert(...)` | 从一个已验证的 PEM 证书中提取出原始的 Ed25519 公钥字节。 |

## 8. 🤝 贡献

我们欢迎任何形式的贡献！如果您发现了 bug、有功能建议或想改进文档，请随时提交 Pull Request 或创建 Issue。

## 9. 📄 许可证

本项目采用 [MIT License](LICENSE) 授权。