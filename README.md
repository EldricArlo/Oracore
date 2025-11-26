<div align="center">
  <img src="./src/media/icon-256.png" alt="Oracipher Icon" width="128">
  <h1 style="border-bottom: none;">Oracipher Core</h1>

# High-Security Hybrid Encryption Kernel Library

| Build & Test | License | Language | Dependencies |
| :---: | :---: | :---: | :---: |
| ![Build Status](https://img.shields.io/badge/tests-passing-brightgreen) | ![License](https://img.shields.io/badge/license-Dual--Licensed-blue) | ![Language](https://img.shields.io/badge/language-C11-purple) | ![Libsodium](https://img.shields.io/badge/libsodium-v1.0.18+-brightgreen) ![OpenSSL](https://img.shields.io/badge/OpenSSL-v3.0+-0075A8) ![Libcurl](https://img.shields.io/badge/libcurl-v7.68+-E5522D) |

</div>

English | [简体中文](./languages/README_zh_CN.md) | [繁體中文](./languages/README_zh_TW.md) | [Português](./languages/README_pt_BR.md) | [Español](./languages/README_es_ES.md) | [日本語](./languages/README_ja_JP.md) | [Русский](./languages/README_ru_RU.md) | [العربية](./languages/README_ar_AR.md) | [Türkçe](./languages/README_tr_TR.md) |

---

### **Table of Contents**
1.  [Project Vision & Core Principles](#1-project-vision--core-principles)
2.  [Core Features](#2-core-features)
3.  [Project Structure](#3-project-structure)
4.  [Quick Start](#4-quick-start)
    *   [4.1 Dependencies](#41-dependencies)
    *   [4.2 Critical Security Configuration: The Pepper](#42-critical-security-configuration-the-pepper)
    *   [4.3 Compilation & Testing](#43-compilation--testing)
    *   [4.4 Windows Deployment Security (CRITICAL)](#44-windows-deployment-security-critical)
5.  [Usage Guide](#5-usage-guide)
    *   [5.1 Using as a Command-Line Tool (`hsc_cli` & `test_ca_util`)](#51-using-as-a-command-line-tool-hsc_cli--test_ca_util)
    *   [5.2 Using as a Library in Your Project](#52-using-as-a-library-in-your-project)
6.  [Deep Dive: Technical Architecture](#6-deep-dive-technical-architecture)
7.  [Advanced Configuration: Enhancing Security & Network Compatibility](#7-advanced-configuration-enhancing-security--network-compatibility)
8.  [Advanced Topic: Encryption Mode Comparison](#8-advanced-topic-encryption-mode-comparison)
9.  [Core API Reference (`include/hsc_kernel.h`)](#9-core-api-reference-includehsc_kernelh)
10. [Contributing](#10-contributing)
11. [Certificate Notes](#11-certificate-notes)
12. [License - Dual-Licensing Model](#12-license---dual-licensing-model)

---

## 1. Project Vision & Core Principles

This project is a security-centric, advanced hybrid encryption kernel library implemented in C11. It aims to provide a battle-tested blueprint for combining industry-leading cryptographic libraries (**libsodium**, **OpenSSL**, **libcurl**) into a robust, reliable, and easy-to-use end-to-end encryption solution.

Our design adheres to the following core security principles:

*   **Choose Vetted, Modern Cryptography:** We never roll our own crypto. We only use modern cryptographic primitives that are widely recognized by the community and resistant to side-channel attacks.
*   **Defense-in-Depth:** Security does not rely on any single layer. We implement protections at multiple levels, including memory management, API design, protocol flow, and **robust handling of all external inputs to prevent resource exhaustion attacks**.
*   **Secure Defaults & "Fail-Closed" Policy:** The system's default behavior must be secure. When faced with an uncertain state (e.g., unable to verify certificate revocation status), the system must choose to fail and terminate the operation (fail-closed) rather than proceed.
*   **Minimize Sensitive Data Exposure:** We strictly control the lifecycle, scope, and residency of critical data like private keys in memory, keeping them to the absolute minimum necessary.

## 2. Core Features

*   **Robust Hybrid Encryption Model:**
    *   **Symmetric Encryption:** Provides AEAD stream encryption (for large data blocks) and one-shot AEAD encryption (for small data blocks) based on **XChaCha20-Poly1305**.
    *   **Asymmetric Encryption:** Uses **X25519** (based on Curve25519) for a Key Encapsulation Mechanism (KEM).
    *   **[FIX] Ephemeral Session Keys (Sender Compromise Resistance):** The protocol generates a fresh ephemeral key pair for every encryption session. This ensures that even if the **sender's** long-term private key is compromised in the future, past messages sent by them cannot be decrypted (protecting against passive decryption of recorded traffic). *Note: This does not constitute "Perfect Forward Secrecy" in the strictest sense (Double Ratchet), as a compromise of the recipient's long-term key would still allow decryption of past messages.*

*   **Modern Cryptographic Primitive Stack:**
    *   **Key Derivation:** Employs **Argon2id**, the winner of the Password Hashing Competition, to effectively resist GPU and ASIC cracking attempts.
    *   **Digital Signatures:** Leverages **Ed25519** for high-speed, high-security digital signature capabilities.
    *   **Unified Keys:** Cleverly utilizes the feature that Ed25519 keys can be safely converted to X25519 keys, allowing a single master key pair to satisfy both signing and encryption needs.

*   **Comprehensive Public Key Infrastructure (PKI) Support:**
    *   **Certificate Lifecycle:** Supports the generation of X.509 v3 compliant Certificate Signing Requests (CSRs).
    *   **Strict Certificate Validation:** Provides a standardized certificate validation process, including trust chain, validity period, and subject matching.
    *   **Mandatory Revocation Checking (OCSP):** Features built-in, strict Online Certificate Status Protocol (OCSP) checks with a "fail-closed" policy. If the certificate's good standing cannot be confirmed, the operation is immediately aborted.
    *   **[NEW] Anti-Replay Protection:** Enforces the use of **Nonces** in OCSP requests/responses to prevent replay attacks.

*   **Rock-Solid Memory Safety:**
    *   Exposes `libsodium`'s secure memory functions through the public API, allowing clients to handle sensitive data (like session keys) safely.
    *   **[Securely Documented]** All internal private keys **and other critical secrets (e.g., key seeds, intermediate hash values)** are stored in locked memory, **preventing them from being swapped to disk by the OS**, and are securely zeroed before being freed. Boundaries with third-party libraries (like OpenSSL) are carefully managed. When sensitive data must cross into standard memory regions (e.g., passing a seed to OpenSSL in `generate_csr`), this library employs defense-in-depth techniques (such as immediately clearing memory buffers after use) to mitigate the inherent risks, representing a best-practice approach when interacting with non-secure-memory-aware libraries.
    *   **[NEW] API Boundary Hardening:** All public APIs now enforce strict output buffer size checks (`_max_len` parameters) to prevent buffer overflows, even if the caller miscalculates allocation sizes.

*   **High-Quality Engineering Practices:**
    *   **Clean API Boundary:** Provides a single public header file, `hsc_kernel.h`, which encapsulates all internal implementation details using opaque pointers, achieving high cohesion and low coupling.
    *   **Comprehensive Test Suite:** Includes a suite of unit and integration tests covering core cryptography, PKI, and high-level API functions to ensure code correctness and reliability.
    *   **Decoupled Logging System:** Implements a callback-based logging mechanism, giving the client application full control over how and where log messages are displayed, making the library suitable for any environment.
    *   **Exhaustive Documentation & Examples:** Provides a detailed `README.md`, along with a ready-to-run demo program and a powerful command-line tool.

## 3. Project Structure

The project uses a clean, layered directory structure to achieve separation of concerns.

```.
├── include/
│   └── hsc_kernel.h      # [Core] The single public API header
├── src/                  # Source Code
│   ├── common/           # Common internal modules (secure memory, logging)
│   ├── core_crypto/      # Core crypto internal modules (libsodium wrappers)
│   ├── pki/              # PKI internal modules (OpenSSL, libcurl wrappers)
│   ├── hsc_kernel.c      # [Core] Implementation of the public API
│   ├── main.c            # API Usage Example: End-to-end demo program
│   └── cli.c             # API Usage Example: Powerful command-line tool
├── docs/
│   └── PEPPER_GUIDE.md   # [Doc] Critical Security Guide for Production Ops
├── tests/                # Unit tests and test utilities
│   ├── test_*.c          # Unit tests for various modules
│   ├── test_api_integration.c # End-to-end tests for high-level APIs
│   ├── test_helpers.h/.c # Test helper functions (CA generation, signing)
│   └── test_ca_util.c    # Source code for the standalone test CA utility
├── Makefile              # Build and task management script
└── README.md             # This project's documentation
```

## 4. Quick Start

### 4.1 Dependencies

*   **Build Tools:** `make`
*   **C Compiler:** `gcc` or `clang` (with C11 and `-Werror` support)
*   **libsodium:** (`libsodium-dev`)
*   **OpenSSL:** **v3.0** or newer is recommended (`libssl-dev`)
*   **libcurl:** (`libcurl4-openssl-dev`)

**Security Note on Dependencies:** The project's build system (`CMakeLists.txt`) will automatically check the versions of your installed dependencies and issue a **FATAL ERROR** if OpenSSL is older than v3.0, and a **SECURITY WARNING** if OpenSSL or Libcurl have known critical vulnerabilities (e.g., CVE-2023-38545 for Libcurl). **Always pay attention to these warnings and keep your system libraries up to date.**

### 4.2 Critical Security Configuration: The Pepper

> **🚨 CRITICAL PRODUCTION WARNING: READ THIS BEFORE DEPLOYMENT**
>
> Oracipher Core enhances the security of its key derivation function (Argon2id) with a system-wide secret known as a "pepper". You **MUST** provide this pepper via an environment variable named `HSC_PEPPER_HEX`.
>
> **Failure to manage this secret correctly will lead to TOTAL DATA LOSS.**
>
> 👉 **Please read the mandatory operational guide:** [docs/PEPPER_GUIDE.md](./docs/PEPPER_GUIDE.md)
>
> This guide covers how to securely inject the pepper in **Systemd, Docker, and Kubernetes** environments.

**For Development & Testing ONLY:**
You can generate a temporary random pepper for local testing. **DO NOT use this method for production.**

```bash
# Generate a random 32-byte pepper and display it as a hex string
export HSC_PEPPER_HEX=$(openssl rand -hex 32)

# You can verify that it has been set
echo $HSC_PEPPER_HEX
```

### 4.3 Compilation & Testing

The project is designed to be highly portable and avoids platform-specific hardcoded paths, ensuring it builds and runs correctly on all supported systems.

1.  **Compile All Targets (library, demo, CLI, tests):**
    ```bash
    make all
    ```

2.  **Run the Comprehensive Test Suite (Critical Step):**
    ```bash
    make run-tests
    ```
    > **Important Note on Expected OCSP Test Behavior**
    >
    > One test case in `test_pki_verification` intentionally validates a certificate pointing to a non-existent local OCSP server (`http://127.0.0.1:8888`). The network request will fail, at which point the `hsc_verify_user_certificate` function **must** return `-13` (the error code for `HSC_ERROR_CERT_OCSP_UNAVAILABLE`). The test program asserts this specific return value.
    >
    > This "failure" is the **expected and correct behavior**, as it perfectly demonstrates that our "fail-closed" security policy is correctly implemented: **if the revocation status of a certificate cannot be confirmed for any reason, it is treated as invalid.**

3.  **Run the Demo Program:**
    ```bash
    ./bin/hsc_demo
    ```

4.  **Explore the Command-Line Tool:**
    ```bash
    ./bin/hsc_cli
    ```

5.  **Clean Up Build Files:**
    ```bash
    make clean
    ```

### 4.4 Windows Deployment Security (CRITICAL)

**[UPDATED] Core Dump Protection on Windows**

On Linux/Unix systems, this library automatically disables core dumps to prevent sensitive keys from being written to disk during a crash.

On **Windows**, this library attempts to perform **Active Defense** by programmatically invoking the Windows Error Reporting (WER) API (`WerAddExcludedApplication`) to exclude the current process from crash dumps.

**However, as a Defense-in-Depth measure (Fallback Strategy):**
To secure your environment against potential API failures or OS-level overrides, you are **STRONGLY ADVISED** to manually configure the Registry:

1.  Open `regedit`.
2.  Navigate to: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps`
3.  Create or modify the value `DumpCount` to `0` (DWORD).
4.  Alternatively, disable WER entirely if your security policy requires strict memory confidentiality.

**Failure to ensure these protections may result in decrypted session keys or private keys persisting on the physical disk after an application crash.**

## 5. Usage Guide

### 5.1 Using as a Command-Line Tool (`hsc_cli` & `test_ca_util`)

This section provides a complete, self-contained workflow demonstrating how two users, Alice and Bob, can perform a secure file exchange using the provided command-line tools.

> **⚠️ CRITICAL: OFFLINE ENVIRONMENTS & NETWORK REQUIREMENTS**
>
> This tool enforces a strict **"Fail-Closed"** security policy regarding certificate revocation. **Every time** you verify a certificate (or encrypt to a certificate), the tool attempts to contact the Issuing CA's OCSP server.
>
> *   **If you are offline:** The operation will **FAIL**.
> *   **If the OCSP server is blocked:** The operation will **FAIL**.
> *   **[NEW] OCSP Nonce Requirement:** The OCSP Responder **MUST** support the OCSP Nonce extension. If the server response does not contain a matching Nonce, the operation will **FAIL** to prevent Replay Attacks.
>
> **Planning:** Ensure your environment has outbound network access to the OCSP URLs defined in your certificates. This tool is **not designed for air-gapped (offline) systems** unless you use the "Direct Key" mode (Option C) or configure a local OCSP responder.

**Tool Roles:**
*   `./bin/test_ca_util`: A helper utility that simulates a Certificate Authority (CA), responsible for generating a root certificate and signing user certificates.
*   `./bin/hsc_cli`: The core client tool for key generation, CSR creation, certificate validation, and file encryption/decryption.

**Complete Workflow Example: Alice Encrypts a File and Sends It Securely to Bob**

1.  **(Setup) Create a Test Certificate Authority (CA):**
    *We use `test_ca_util` to generate a root CA key and a self-signed certificate.*
    ```bash
    ./bin/test_ca_util gen-ca ca.key ca.pem
    ```

2.  **(Alice & Bob) Generate Their Master Key Pairs:**
    ```bash
    ./bin/hsc_cli gen-keypair alice
    ./bin/hsc_cli gen-keypair bob
    ```
    *This creates `alice.key`, `alice.pub`, `bob.key`, and `bob.pub`.*

3.  **(Alice & Bob) Generate Certificate Signing Requests (CSRs):**
    ```bash
    ./bin/hsc_cli gen-csr alice.key "alice@example.com"
    ./bin/hsc_cli gen-csr bob.key "bob@example.com"
    ```
    *This creates `alice.csr` and `bob.csr`.*

4.  **(CA) Sign the CSRs to Issue Certificates:**
    *The CA uses its private key (`ca.key`) and certificate (`ca.pem`) to sign the CSRs.*
    ```bash
    ./bin/test_ca_util sign alice.csr ca.key ca.pem alice.pem
    ./bin/test_ca_util sign bob.csr ca.key ca.pem bob.pem
    ```
    *Alice and Bob now have their official certificates, `alice.pem` and `bob.pem`.*

5.  **(Alice) Verifies Bob's Certificate Before Sending:**
    *Alice uses the trusted CA certificate (`ca.pem`) to verify Bob's identity. This is a critical step before trusting his certificate.*
    ```bash
    ./bin/hsc_cli verify-cert bob.pem --ca ca.pem --user "bob@example.com"
    ```

6.  **(Alice) Encrypts a File for Bob:**
    *Alice now has several options:*

    **Option A: Certificate-Based with Validation (Secure Default & Recommended)**
    > This is the standard, secure way to operate. The tool **requires** Alice to provide the CA certificate and the expected username to perform a full, strict validation of Bob's certificate before encrypting.
    ```bash
    echo "This is top secret information." > secret.txt
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key --ca ca.pem --user "bob@example.com"
    ```

    **Option B: Certificate-Based without Validation (Dangerous - Expert Use Only)**
    > If Alice is absolutely certain of the certificate's authenticity and wishes to skip validation, she must explicitly use the `--no-verify` flag. **This is not recommended.**
    ```bash
    # Use with extreme caution!
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key --no-verify
    ```

    **Option C: Direct Key Mode (Advanced - For Pre-Trusted Keys)**
    *If Alice has already obtained Bob's public key (`bob.pub`) through a secure, trusted channel, she can encrypt to it directly, bypassing all certificate logic. **The tool will show a severe security warning and require explicit user confirmation before proceeding.**
    ```bash
    ./bin/hsc_cli encrypt secret.txt --recipient-pk-file bob.pub --from alice.key
    ```
    *All options create `secret.txt.hsc`. Alice can now send `secret.txt.hsc` and her certificate `alice.pem` to Bob.*

7.  **(Bob) Decrypts the File Upon Receipt:**
    *Bob uses his private key (`bob.key`) to decrypt the file. Depending on how Alice encrypted it, he will need either her certificate (`alice.pem`) or her raw public key (`alice.pub`).*

    **If Alice Used Option A or B (Certificate):**
    ```bash
    ./bin/hsc_cli decrypt secret.txt.hsc --to bob.key --from alice.pem
    ```

    **If Alice Used Option C (Direct Key):**
    ```bash
    ./bin/hsc_cli decrypt secret.txt.hsc --to bob.key --sender-pk-file alice.pub
    ```
    *Both commands will produce `secret.txt.decrypted`.*
    ```bash
    cat secret.txt.decrypted
    ```

### 5.2 Using as a Library in Your Project

`src/main.c` serves as an excellent integration example. A typical API call flow is as follows:

1.  **Global Initialization & Log Setup:** Call `hsc_init()` on startup and register a log callback.
    ```c
    #include "hsc_kernel.h"
    #include <stdio.h>

    // Define a simple logging function for your application
    void my_app_logger(int level, const char* message) {
        // Example: Print errors to stderr, info to stdout
        if (level >= 2) { // 2 = ERROR
            fprintf(stderr, "[HSC_LIB_ERROR] %s\n", message);
        } else {
            printf("[HSC_LIB_INFO] %s\n", message);
        }
    }

    int main() {
        // CRITICAL: Ensure HSC_PEPPER_HEX is set in the environment before this call!
        if (hsc_init(NULL, NULL) != HSC_OK) {
            // Handle fatal error
        }
        // Register your logging function with the library
        hsc_set_log_callback(my_app_logger);

        // ... Your code ...
        hsc_cleanup();
        return 0;
    }
    ```

2.  **Sender (Alice) Encrypts Data:**
    ```c
    // 1. Generate a one-time session key
    unsigned char session_key[HSC_SESSION_KEY_BYTES];
    hsc_random_bytes(session_key, sizeof(session_key));

    // 2. Encrypt data with the session key using AEAD (for small data)
    const char* message = "Secret message";
    // ... (encryption logic is the same as in the example) ...

    // 3. Verify the recipient's (Bob's) certificate
    if (hsc_verify_user_certificate(bob_cert_pem, ca_pem, "bob@example.com" ) != HSC_OK) {
        // Certificate is invalid, abort! The library will log details via your callback.
    }

    // 4. Extract Bob's public key from his certificate
    unsigned char bob_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    
    // [NEW in v5.2] Pass buffer size for safety
    if (hsc_extract_public_key_from_cert(bob_cert_pem, bob_pk, sizeof(bob_pk)) != HSC_OK) {
        // Handle extraction error
    }

    // 5. Encapsulate the session key
    // ... (encapsulation logic is the same as in the example) ...
    ```

3.  **Receiver (Bob) Decrypts Data:**
    *The decryption logic remains the same, but any internal errors during decapsulation or AEAD decryption will now be reported through your registered `my_app_logger` callback instead of polluting `stderr` directly.*

## 6. Deep Dive: Technical Architecture

The core of this project is a hybrid encryption model that combines the advantages of asymmetric and symmetric cryptography to achieve both secure and efficient data transfer.

**Data Flow & Key Relationship Diagram:**

```
SENDER (ALICE)                                            RECEIVER (BOB)
========================================================================
[ Plaintext ] --> Generate [ Session Key ]
                      |           |
(Symmetric Encrypt) <-'           '-> (Asymmetric Encapsulate) using: Bob's Public Key, Alice's Private Key
      |                                             |
[ Encrypted Data ]                    [ Encapsulated Session Key ]
      |                                             |
      '---------------------.   .-------------------'
                            |   |
                            v   v
                        [ Data Packet ]
                            |
    ==================>  Over Network/File  =================>
                            |
                        [ Data Packet ]
                            |   |
            .---------------'   '-----------------.
            |                                     |
[ Encapsulated Session Key ]              [ Encrypted Data ]
            |                                     |
            v                                     |
(Asymmetric Decapsulate) using: Bob's Private Key, Alice's Public Key
            |                                     |
            v                                     |
       [ Recovered Session Key ] <----$-----' (Symmetric Decrypt)
            |
            v
       [ Plaintext ]
```

## 7. Advanced Configuration: Enhancing Security & Network Compatibility

To adapt to future hardware and security needs without code modification, this project supports configuration via environment variables.

### 7.1 Cryptographic Hardening
*   **`HSC_ARGON2_OPSLIMIT`**: Sets the number of operations (computational rounds) for Argon2id.
*   **`HSC_ARGON2_MEMLIMIT`**: Sets the memory usage in bytes for Argon2id.

**Important Security Note:** This feature can **only be used to strengthen security parameters**. If the values set in the environment variables are lower than the minimum security baselines built into the project, the program will automatically ignore the insecure values and enforce the built-in minimums.

### 7.2 Internal Network Support (SSRF Protection)
By default, Oracipher Core strictly blocks OCSP requests to private IP addresses (e.g., `10.x.x.x`, `192.168.x.x`, `127.0.0.1`) to prevent **Server-Side Request Forgery (SSRF)** attacks.

*   **`HSC_PKI_ALLOW_PRIVATE_IP`**: Set this variable to `1` to allow OCSP requests to private IP addresses.
    *   **Use Case:** Deployment in corporate intranets where private CA/OCSP servers are used.
    *   **Warning:** Enabling this bypasses a critical security filter. Ensure your environment is trusted.

**Usage Example:**

```bash
# Example: Increase ops limit and allow internal OCSP servers.
export HSC_ARGON2_OPSLIMIT=10
export HSC_ARGON2_MEMLIMIT=536870912
export HSC_PKI_ALLOW_PRIVATE_IP=1

# Don't forget the mandatory HSC_PEPPER_HEX variable!
export HSC_PEPPER_HEX=$(openssl rand -hex 32)
./bin/hsc_cli gen-keypair my_strong_key
```

## 8. Advanced Topic: Encryption Mode Comparison

Oracipher Core provides two distinct hybrid encryption workflows, each with different security guarantees. Choosing the right one is critical.

### Certificate-Based Workflow (Default & Recommended)

*   **How it Works:** Uses X.509 certificates to bind a user's identity (e.g., `bob@example.com`) to their public key.
*   **Security Guarantees:**
    *   **Authentication:** Cryptographically verifies that the public key truly belongs to the intended recipient.
    *   **Integrity:** Ensures the certificate has not been tampered with.
    *   **Revocation Checking:** Actively checks via OCSP if the certificate has been revoked by the issuing authority.
*   **When to Use:** In any scenario where the sender and receiver do not have a pre-existing, highly secure channel to exchange public keys. This is the standard for most internet-based communication.

### Direct Key (Raw) Workflow (Advanced)

*   **How it Works:** Bypasses all PKI and certificate logic, encrypting directly to a raw public key file.
*   **Security Guarantees:**
    *   Provides the same level of **confidentiality** and **integrity** for the encrypted data itself as the certificate mode.
*   **Security Trade-offs:**
    > **[CRITICAL SECURITY WARNING]**
    >
    > *   **No Authentication:** This mode **does not** and **cannot** verify the identity of the key's owner. The user is solely responsible for ensuring the authenticity of the public key they are using.
    > *   **Risk of Impersonation:** Using an incorrect or malicious public key will result in the data being encrypted for the wrong party (an attacker) without any warning from the system.
    > *   **The `hsc_cli` tool will force you to acknowledge a detailed security warning before proceeding with this mode.**

*   **When to Use:** **ONLY** in closed systems or specific protocols where public keys have been exchanged and verified through an independent, highly trusted out-of-band mechanism.

## 9. Core API Reference (`include/hsc_kernel.h`)

### Initialization & Cleanup
| Function | Description |
| :--- | :--- |
| `int hsc_init(config, pepper)` | **(Must be called first)** Initializes the entire library. Accepts config & pepper. |
| `void hsc_cleanup()` | Call before program exit to free global resources. |

### Key Management
| Function | Description |
| :--- | :--- |
| `hsc_master_key_pair* hsc_generate_master_key_pair()` | Generates a new master key pair. |
| `hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(...)` | Loads a private key from a file. |
| `int hsc_save_master_key_pair(...)` | Saves a key pair to files. |
| `void hsc_free_master_key_pair(hsc_master_key_pair** kp)` | Securely frees a master key pair. |
| `int hsc_get_master_public_key(kp, out, max_len)` | **[New]** Extracts the raw public key from a key pair handle. |

### PKI & Certificates
| Function | Description |
| :--- | :--- |
| `int hsc_generate_csr(...)` | Generates a PEM-formatted Certificate Signing Request (CSR). |
| `int hsc_verify_user_certificate(...)` | **(Core)** Performs full certificate validation (chain, validity, subject, OCSP). |
| `int hsc_extract_public_key_from_cert(pem, out, max_len)` | Extracts a public key from a verified certificate. |

### Key Encapsulation (Asymmetric)
| Function | Description |
| :--- | :--- |
| `int hsc_encapsulate_session_key(out, max_len, ...)` | Encrypts a session key using the recipient's public key (Auth KEM). |
| `int hsc_decapsulate_session_key(out, max_len, ...)` | Decrypts a session key using the recipient's private key (Auth KEM). |

### Stream Encryption (Symmetric, for large files)
| Function | Description |
| :--- | :--- |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(...)` | Creates an encryption stream state object. |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(...)` | Creates a decryption stream state object. |
| `int hsc_crypto_stream_push(...)` | Encrypts a chunk of data in a stream. |
| `int hsc_crypto_stream_pull(...)` | Decrypts a chunk of data in a stream. |
| `void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state)` | Frees a stream state object. |
| `int hsc_hybrid_encrypt_stream_raw(...)` | Performs full hybrid encryption on a file using a raw public key. |
| `int hsc_hybrid_decrypt_stream_raw(...)` | Performs full hybrid decryption on a file using a raw public key. |

### Data Encryption (Symmetric, for small data)
| Function | Description |
| :--- | :--- |
| `int hsc_aead_encrypt(out, max_len, ...)` | Performs authenticated encryption on a **small chunk of data** using AEAD. |
| `int hsc_aead_decrypt(out, max_len, ...)` | Decrypts and verifies data encrypted by `hsc_aead_encrypt`. |

### Secure Memory
| Function | Description |
| :--- | :--- |
| `void* hsc_secure_alloc(size_t size)` | Allocates a protected, non-swappable block of memory. |
| `void hsc_secure_free(void* ptr)` | Securely zeroes and frees a protected block of memory. |

### Logging
| Function | Description |
| :--- | :--- |
| `void hsc_set_log_callback(hsc_log_callback callback)` | **[New]** Registers a callback function to handle all internal library logs. |

## 10. Contributing

We welcome all forms of contribution! If you find a bug, have a feature suggestion, or want to improve the documentation, please feel free to submit a Pull Request or create an Issue.

## 11. Certificate Notes

This project uses an **X.509 v3** certificate system to bind public keys to user identities (e.g., `alice@example.com`), thereby establishing trust. The certificate validation process includes:
*   **Signature Chain Validation**: Verifies trust back to the Root CA.
*   **Validity Period Checks**: Ensures the certificate is not expired.
*   **Subject Identity Verification**: Matches the username.
*   **Strict Revocation Checking (OCSP)**: Checks status with the issuing CA under a "fail-closed" policy.
*   **Anti-Replay (Nonce) Checks**: Ensures OCSP responses are fresh and generated specifically for the current request.

## 12. License - Dual-Licensing Model

This project is distributed under a **dual-license** model:

### 1. GNU Affero General Public License v3.0 (AGPLv3)
This license is suitable for open-source projects, academic research, and personal study. It requires that any derivative works, whether modified or offered as a service over a network, must also have their full source code made available under the AGPLv3.

### 2. Commercial License
A commercial license must be obtained for any closed-source commercial applications, products, or services. If you do not wish to be bound by the open-source terms of the AGPLv3, you must acquire a commercial license.

**To obtain a commercial license, please contact: `eldric520lol@gmail.com`**
