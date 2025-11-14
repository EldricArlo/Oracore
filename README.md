<div align="center">
  <img src="./src/media/icon-256.png" alt="Oracipher Icon" width="128">
  <h1 style="border-bottom: none;">Oracipher Core</h1>

# High-Security Hybrid Encryption Kernel Library

| Build & Test | License | Language | Dependencies |
| :---: | :---: | :---: | :---: |
| ![Build Status](https://img.shields.io/badge/tests-passing-brightgreen) | ![License](https://img.shields.io/badge/license-Dual--Licensed-blue) | ![Language](https://img.shields.io/badge/language-C11-purple) | ![Libsodium](https://img.shields.io/badge/libsodium-v1.0.18+-brightgreen) ![OpenSSL](https://img.shields.io/badge/OpenSSL-v3.0+-0075A8) ![Libcurl](https://img.shields.io/badge/libcurl-v7.68+-E5522D) |

</div>

English | [简体中文](./languages/README_zh_CN.md) | [繁體中文](./languages/README_zh_TW.md) | [Português](./languages/README_pt_BR.md) | [Español](./languages/README_es_ES.md) | [日本語](./languages/README_ja_JP.md) | [Русский](./languages/README_ru_RU.md) | [العربية](./languages/README_ar_AR.md) | [Türkçe](./languages/README_tr_TR.md) |

## 1. Project Vision & Core Principles

This project is a security-focused, high-level hybrid encryption kernel library implemented using the C11 standard. It aims to provide a battle-tested blueprint demonstrating how to combine industry-leading cryptographic libraries (**libsodium**, **OpenSSL**, **libcurl**) into a robust, reliable, and easy-to-use end-to-end encryption solution.

Our design adheres to the following core security principles:

*   **Choose Vetted, Modern Cryptography:** Never implement cryptographic algorithms from scratch. Exclusively use modern, side-channel resistant cryptographic primitives that are widely recognized by the community.
*   **Defense-in-Depth:** Security does not rely on any single layer. We implement multiple layers of protection, from memory management and API design to protocol flows.
*   **Secure Defaults & "Fail-Closed" Policy:** The system's default behavior must be secure. When faced with an uncertain state (e.g., inability to verify certificate revocation status), the system must choose to fail and terminate the operation (Fail-Closed) rather than proceeding.
*   **Minimize Sensitive Data Exposure:** The lifecycle, scope, and memory-residency time of critical data, such as private keys, must be strictly controlled to the absolute minimum necessary.

## 2. Core Features

*   **Robust Hybrid Encryption Model:**
    *   **Symmetric Encryption:** Provides AEAD stream encryption based on **XChaCha20-Poly1305** for large data chunks and one-shot AEAD encryption for smaller data blocks.
    *   **Asymmetric Encryption:** Uses **X25519** (based on Curve2519) for key encapsulation of the symmetric session key, ensuring only the intended recipient can decrypt it.

*   **Modern Cryptographic Primitive Stack:**
    *   **Key Derivation:** Employs **Argon2id**, the winner of the Password Hashing Competition, to effectively resist GPU and ASIC cracking attempts.
    *   **Digital Signature:** Utilizes **Ed25519** to provide high-speed, high-security digital signature capabilities.
    *   **Key Unification:** Cleverly leverages the property that Ed25519 keys can be safely converted to X25519 keys, allowing a single master key pair to satisfy both signing and encryption needs.

*   **Comprehensive Public Key Infrastructure (PKI) Support:**
    *   **Certificate Lifecycle:** Supports the generation of X.509 v3 compliant Certificate Signing Requests (CSRs).
    *   **Strict Certificate Validation:** Provides a standardized certificate validation process, including trust chain, validity period, and subject matching.
    *   **Mandatory Revocation Check (OCSP):** Features a built-in, strict Online Certificate Status Protocol (OCSP) check with a "Fail-Closed" policy, immediately aborting operations if the certificate's good standing cannot be confirmed.

*   **Rock-Solid Memory Safety:**
    *   Exposes `libsodium`'s secure memory functions through the public API, allowing clients to safely handle sensitive data (like session keys).
    *   All internal private keys **and other critical secrets (like key seeds and intermediate hashes)** are stored in locked memory, **preventing them from being swapped to disk by the OS**, and are securely wiped before being freed.
    *   Data boundaries with third-party libraries (like OpenSSL) are meticulously managed. The library employs deep-defense techniques, such as double-cleansing memory buffers, to mitigate inherent risks when sensitive data must cross into standard memory regions.

*   **High-Quality Engineering Practices:**
    *   **Clean API Boundary:** Provides a single public header `hsc_kernel.h` that encapsulates all internal implementation details using opaque pointers, achieving high cohesion and low coupling.
    *   **[ENHANCED] Comprehensive Test Suite:** Includes a suite of unit and integration tests covering core cryptographic, PKI, and high-level API functions to ensure code correctness and reliability.
    *   **Decoupled Logging:** Implements a callback-based logging mechanism, giving the client application full control over how and where log messages are displayed, making the library suitable for any environment.
    *   **Thorough Documentation & Examples:** Offers a detailed `README.md` along with a ready-to-run demo program and a powerful command-line utility.

## 3. Project Structure

The project uses a clean, layered directory structure to achieve separation of concerns.

```.
├── include/
│   └── hsc_kernel.h      # [CORE] The single public API header file
├── src/                  # Source code
│   ├── common/           # Common internal modules (secure memory, logging)
│   ├── core_crypto/      # Core crypto internal modules (libsodium wrappers)
│   ├── pki/              # PKI internal modules (OpenSSL, libcurl wrappers)
│   ├── hsc_kernel.c      # [CORE] Implementation of the public API
│   ├── main.c            # API usage example: end-to-end demo program
│   └── cli.c             # API usage example: powerful command-line tool
├── tests/                # Unit tests and test utilities
│   ├── test_*.c          # Unit tests for various modules
│   ├── test_api_integration.c # [NEW] End-to-end tests for high-level APIs
│   ├── test_helpers.h/.c # Test helper functions (CA generation, signing)
│   └── test_ca_util.c    # Source for the standalone test CA utility
├── Makefile              # Build and task management script
└── README.md             # This project's documentation
```

## 4. Quick Start

### 4.1. Dependencies

*   **Build Tools:** `make`
*   **C Compiler:** `gcc` or `clang` (with C11 and `-Werror` support)
*   **libsodium:** (`libsodium-dev`)
*   **OpenSSL:** **v3.0** or later is recommended (`libssl-dev`)
*   **libcurl:** (`libcurl4-openssl-dev`)

**Installation on Popular Systems:**

*   **Debian/Ubuntu:**
    ```bash
    sudo apt-get update
    sudo apt-get install build-essential libsodium-dev libssl-dev libcurl4-openssl-dev
    ```
*   **Fedora/RHEL/CentOS:**
    ```bash
    sudo dnf install gcc make libsodium-devel openssl-devel libcurl-devel
    ```
*   **macOS (using Homebrew):**
    ```bash
    brew install libsodium openssl@3 curl
    ```

### 4.2. Compilation and Testing

The project is designed to be highly portable and avoids platform-specific hardcoded paths, ensuring it builds and runs correctly across all supported systems.

1.  **Compile all targets (library, demo, CLI, tests):**
    ```bash
    make all
    ```

2.  **Run the comprehensive test suite (critical step):**
    ```bash
    make run-tests
    ```
    > **Note on Expected OCSP Test Behavior**
    >
    > One test case in `test_pki_verification` intentionally validates a certificate pointing to a non-existent local OCSP server (`http://127.0.0.1:8888`). The network request will fail, and the `hsc_verify_user_certificate` function **must** return `-12` (the error code for `HSC_ERROR_CERT_REVOKED_OR_OCSP_FAILED`). The test asserts this specific return value. This "failure" is the desired outcome, as it proves that our "Fail-Closed" security policy is correctly implemented: if revocation status cannot be confirmed for any reason, the certificate is treated as invalid.

3.  **Run the demo program:**
    ```bash
    ./bin/hsc_demo
    ```

4.  **Explore the command-line tool:**
    ```bash
    ./bin/hsc_cli
    ```

5.  **Clean up build files:**
    ```bash
    make clean
    ```

## 5. Usage Guide

### 5.1. As a Command-Line Tool (`hsc_cli` & `test_ca_util`)

This section provides a complete, self-contained workflow for secure file exchange between two users, Alice and Bob, using the provided command-line tools.

**Complete Workflow Example: Alice encrypts a file and sends it securely to Bob**

1.  **(Setup) Create a Test Certificate Authority (CA):**
    *We use `test_ca_util` to generate a root CA key and a self-signed certificate.*
    ```bash
    ./bin/test_ca_util gen-ca ca.key ca.pem
    ```

2.  **(Alice & Bob) Generate their master key pairs:**
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

4.  **(CA) Sign the CSRs to issue certificates:**
    *The CA uses its private key (`ca.key`) and certificate (`ca.pem`) to sign the CSRs.*
    ```bash
    ./bin/test_ca_util sign alice.csr ca.key ca.pem alice.pem
    ./bin/test_ca_util sign bob.csr ca.key ca.pem bob.pem
    ```
    *Now Alice and Bob have their official certificates, `alice.pem` and `bob.pem`.*

5.  **(Alice) Verify Bob's certificate before sending:**
    *Alice uses the trusted CA certificate (`ca.pem`) to verify Bob's identity. This is a crucial step before trusting his certificate.*
    ```bash
    ./bin/hsc_cli verify-cert bob.pem --ca ca.pem --user "bob@example.com"
    ```

6.  **(Alice) Encrypt a file for Bob:**
    *Alice now has multiple options:*

    **Option A: Certificate-Based with Verification (Secure Default & Recommended)**
    > This is the standard, secure way to operate. The tool **requires** Alice to provide the CA certificate and expected username to perform a full, strict validation of Bob's certificate before encrypting.
    ```bash
    echo "This is top secret information." > secret.txt
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key --ca ca.pem --user "bob@example.com"
    ```

    **Option B: Certificate-Based without Verification (Dangerous - for experts only)**
    > If Alice is absolutely certain of the certificate's authenticity and wishes to skip verification, she must explicitly use the `--no-verify` flag. **This is not recommended.**
    ```bash
    # Use with extreme caution!
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key --no-verify
    ```

    **Option C: Direct Key Mode (Advanced - for pre-trusted keys)**
    *If Alice has obtained Bob's public key (`bob.pub`) through a secure, trusted channel, she can encrypt directly to it, bypassing all certificate logic.*
    ```bash
    ./bin/hsc_cli encrypt secret.txt --recipient-pk-file bob.pub --from alice.key
    ```
    *All options create `secret.txt.hsc`. Alice can now send `secret.txt.hsc` and her certificate `alice.pem` to Bob.*

7.  **(Bob) Decrypt the file upon receipt:**
    *Bob decrypts the file using his private key (`bob.key`). Depending on how Alice encrypted it, he will use either her certificate (`alice.pem`) or her raw public key (`alice.pub`).*

    **If Alice used Option A or B (Certificate):**
    ```bash
    ./bin/hsc_cli decrypt secret.txt.hsc --to bob.key --from alice.pem
    ```

    **If Alice used Option C (Direct Key):**
    ```bash
    ./bin/hsc_cli decrypt secret.txt.hsc --to bob.key --sender-pk-file alice.pub
    ```
    *Both commands will produce `secret.txt.decrypted`.*
    ```bash
    cat secret.txt.decrypted
    ```

### 5.2. As a Library in Your Project

`src/main.c` serves as an excellent integration example. The typical API call flow is as follows:

1.  **Global Initialization & Logging Setup:** Call `hsc_init()` at startup and register a logging callback.
    ```c
    #include "hsc_kernel.h"
    #include <stdio.h>

    // Define a simple logger function for your application
    void my_app_logger(int level, const char* message) {
        // Example: Print errors to stderr and info to stdout
        if (level >= 2) { // 2 = ERROR
            fprintf(stderr, "[HSC_LIB_ERROR] %s\n", message);
        } else {
            printf("[HSC_LIB_INFO] %s\n", message);
        }
    }

    int main() {
        if (hsc_init() != HSC_OK) {
            // Handle fatal error
        }
        // Register your logger with the library
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
    // ... (encryption logic remains the same) ...

    // 3. Verify the recipient's (Bob's) certificate
    if (hsc_verify_user_certificate(bob_cert_pem, ca_pem, "bob@example.com") != HSC_OK) {
        // Certificate is invalid, abort! The library will have logged details via your callback.
    }

    // 4. Extract Bob's public key from his certificate
    unsigned char bob_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    if (hsc_extract_public_key_from_cert(bob_cert_pem, bob_pk) != HSC_OK) {
        // Handle extraction error
    }

    // 5. Encapsulate the session key
    // ... (encapsulation logic remains the same) ...
    ```

3.  **Recipient (Bob) Decrypts Data:**
    *The decryption logic remains the same, but any internal errors during decapsulation or AEAD decryption will now be reported through your registered `my_app_logger` callback instead of polluting `stderr` directly.*

## 6. Deep Dive: Technical Architecture

The core of this project is a Hybrid Encryption model, which combines the advantages of asymmetric and symmetric cryptography to achieve both secure and efficient data transmission.

**Data Flow and Key Relationship Diagram:**

```
SENDER (ALICE)                                           RECIPIENT (BOB)
========================================================================
[ Plaintext ] ------> Generates [ Session Key ]
                          |             |
(Symmetric Encrypt) <-----'             '-> (Asymmetric Encapsulate) using: Bob's Pubkey, Alice's Privkey
     |                                          |
[ Encrypted Data ]                         [ Encapsulated Session Key ]
     |                                          |
     '--------------------.  .------------------'
                          |  |
                          v  v
                     [ Data Packet ]
                            |
   ==================>  Over Network/File  =================>
                            |
                     [ Data Packet ]
                          |  |
           .--------------'  '----------------.
           |                                  |
[ Encapsulated Session Key ]         [ Encrypted Data ]
           |                                  |
           v                                  |
(Asymmetric Decapsulate) using: Bob's Privkey, Alice's Pubkey
           |                                  |
           v                                  |
      [ Recovered Session Key ] <--------$----' (Symmetric Decrypt)
           |
           v
      [ Plaintext ]
```

## 7. Advanced Configuration: Enhancing Security via Environment Variables

To adapt to future hardware and security requirements without modifying the code, this project supports **increasing** the computational cost of the key derivation function (Argon2id) via environment variables.

*   **`HSC_ARGON2_OPSLIMIT`**: Sets the number of operations (computational rounds) for Argon2id.
*   **`HSC_ARGON2_MEMLIMIT`**: Sets the memory usage for Argon2id in bytes.

**Important Security Note:** This feature can **only be used to increase security parameters**. If the values set in the environment variables are lower than the minimum security baseline built into the project, the program will automatically ignore these insecure values and enforce the built-in minimums.

**Usage Example:**

```bash
# Example: Increase the operations limit to 10 and the memory limit to 512MB.
# Note: HSC_ARGON2_MEMLIMIT requires the value in bytes.
# 512 * 1024 * 1024 = 536870912 bytes.
export HSC_ARGON2_OPSLIMIT=10
export HSC_ARGON2_MEMLIMIT=536870912

# Running any program in a shell with these variables set will automatically use these stronger parameters.
./bin/hsc_cli gen-keypair my_strong_key
```

## 8. Advanced Topics: Comparing Encryption Modes

Oracipher Core provides two distinct workflows for hybrid encryption, each with different security guarantees. Choosing the right mode is critical.

### Certificate-Based Workflow (Default & Recommended)

*   **How it works:** Uses X.509 certificates to bind a user's identity (e.g., `bob@example.com`) to their public key.
*   **Security Guarantees:**
    *   **Authentication:** Cryptographically verifies that the public key belongs to the intended recipient.
    *   **Integrity:** Ensures the certificate has not been tampered with.
    *   **Revocation Checking:** Actively checks via OCSP if the certificate has been revoked by the Certificate Authority.
*   **When to use:** In any scenario where the sender and receiver do not have a pre-existing, highly secure channel to exchange public keys. This is the standard for most internet-based communication.

### Direct Key (Raw) Workflow (Advanced)

*   **How it works:** Bypasses all PKI and certificate logic, encrypting directly to a raw public key file.
*   **Security Guarantees:**
    *   Provides the same level of **confidentiality** and **integrity** for the encrypted data itself as the certificate mode.
*   **Security Trade-off:**
    *   **NO AUTHENTICATION:** This mode **DOES NOT** verify the identity of the key's owner. The user is solely responsible for ensuring the authenticity of the public key they are using. Using an incorrect or malicious public key will lead to data being encrypted for the wrong party.
*   **When to use:** Only in closed systems or specific protocols where public keys have been exchanged and verified through a separate, trusted, out-of-band mechanism (e.g., keys baked into a secure device's firmware, or verified in person).

## 9. Core API Reference (`include/hsc_kernel.h`)

### Initialization & Cleanup
| Function | Description |
| :--- | :--- |
| `int hsc_init()` | **(Must be called first)** Initializes the entire library. |
| `void hsc_cleanup()` | Call before program exit to release global resources. |

### Key Management
| Function | Description |
| :--- | :--- |
| `hsc_master_key_pair* hsc_generate_master_key_pair()` | Generates a new master key pair. |
| `hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(...)` | Loads a private key from a file. |
| `int hsc_save_master_key_pair(...)` | Saves a key pair to a file. |
| `void hsc_free_master_key_pair(hsc_master_key_pair** kp)` | Securely frees a master key pair. |
| `int hsc_get_master_public_key(const hsc_master_key_pair* kp, ...)` | **[NEW]** Extracts the raw public key from a key pair handle. |

### PKI & Certificates
| Function | Description |
| :--- | :--- |
| `int hsc_generate_csr(...)` | Generates a Certificate Signing Request (CSR) in PEM format. |
| `int hsc_verify_user_certificate(...)` | **(Core)** Performs full certificate validation (chain, validity, subject, OCSP). |
| `int hsc_extract_public_key_from_cert(...)` | Extracts the public key from a verified certificate. |

### Key Encapsulation (Asymmetric)
| Function | Description |
| :--- | :--- |
| `int hsc_encapsulate_session_key(...)` | Encrypts a session key using the recipient's public key. |
| `int hsc_decapsulate_session_key(...)` | Decrypts a session key using the recipient's private key. |

### Stream Encryption (Symmetric, for large files)
| Function | Description |
| :--- | :--- |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(...)` | Creates an encryption stream state object. |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(...)` | Creates a decryption stream state object. |
| `int hsc_crypto_stream_push(...)` | Encrypts a chunk of data in the stream. |
| `int hsc_crypto_stream_pull(...)` | Decrypts a chunk of data in the stream. |
| `void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state)` | Frees the stream state object. |
| `int hsc_hybrid_encrypt_stream_raw(...)` | Performs full hybrid encryption on a file using a raw public key. |
| `int hsc_hybrid_decrypt_stream_raw(...)` | Performs full hybrid decryption on a file using a raw public key. |

### Data Encryption (Symmetric, for small data)
| Function | Description |
| :--- | :--- |
| `int hsc_aead_encrypt(...)` | Performs authenticated encryption on a **small block of data** using AEAD. |
| `int hsc_aead_decrypt(...)` | Decrypts and verifies data encrypted by `hsc_aead_encrypt`. |

### Secure Memory
| Function | Description |
| :--- | :--- |
| `void* hsc_secure_alloc(size_t size)` | Allocates a protected, non-swappable block of memory. |
| `void hsc_secure_free(void* ptr)` | Securely wipes and frees a protected block of memory. |

### Logging
| Function | Description |
| :--- | :--- |
| `void hsc_set_log_callback(hsc_log_callback callback)` | **[NEW]** Registers a callback function to handle all internal library logs. |

## 10. Contributing

We welcome contributions of all forms! If you find a bug, have a feature suggestion, or want to improve the documentation, please feel free to submit a Pull Request or create an Issue.

## 11. Certificate Description

This project uses the **X.509 v3** certificate system to bind a public key to a user identity (e.g., `alice@example.com`), thereby establishing trust. The certificate validation process includes **signature chain verification**, **validity period check**, **subject identity verification**, and **revocation status check (OCSP)**, all under a strict "Fail-Closed" policy.

## 12. License - Dual-License Model

This project is distributed under a **Dual-License** model:

### 1. GNU Affero General Public License v3.0 (AGPLv3)
Suitable for open-source projects, academic research, and personal study. It requires that any modified or network-serviced derivative works must also have their complete source code opened under the AGPLv3.

### 2. Commercial License
Required for any closed-source commercial applications, products, or services. If you do not wish to be bound by the open-source terms of the AGPLv3, you must obtain a commercial license.

**To obtain a commercial license, please contact: `eldric520lol@gmail.com`**
