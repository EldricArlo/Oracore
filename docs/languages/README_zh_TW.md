<div align="center">
  <img src="./src/media/icon-256.png" alt="Oracipher Icon" width="128">
  <h1 style="border-bottom: none;">Oracipher Core</h1>

# 高安全性混合式加密核心函式庫

| Build & Test | License | Language | Dependencies |
| :---: | :---: | :---: | :---: |
| ![Build Status](https://img.shields.io/badge/tests-passing-brightgreen) | ![License](https://img.shields.io/badge/license-Dual--Licensed-blue) | ![Language](https://img.shields.io/badge/language-C11-purple) | ![Libsodium](https://img.shields.io/badge/libsodium-v1.0.18+-brightgreen) ![OpenSSL](https://img.shields.io/badge/OpenSSL-v3.0+-0075A8) ![Libcurl](https://img.shields.io/badge/libcurl-v7.68+-E5522D) |

</div>

---

### **目錄**
1.  [專案願景與核心原則](#1-專案願景與核心原則)
2.  [核心特性](#2-核心特性)
3.  [專案結構](#3-專案結構)
4.  [快速入門](#4-快速入門)
    *   [4.1 依賴環境](#41-依賴環境)
    *   [4.2 編譯與測試](#42-編譯與測試)
5.  [使用指南](#5-使用指南)
    *   [5.1 作為命令列工具使用](#51-作為命令列工具使用hsc_cli--test_ca_util)
    *   [5.2 在您的專案中作為函式庫使用](#52-在您的專案中作為函式庫使用)
6.  [深度剖析：技術架構](#6-深度剖析技術架構)
7.  [進階設定：透過環境變數增強安全性](#7-進階設定透過環境變數增強安全性)
8.  [進階主題：加密模式比較](#8-進階主題加密模式比較)
9.  [核心API參考](#9-核心api參考includehsc_kernelh)
10. [貢獻](#10-貢獻)
11. [憑證說明](#11-憑證說明)
12. [授權許可](#12-授權許可---雙重授權模式)

---

## 1. 專案願景與核心原則

本專案是一個以安全為核心、採用 C11 標準實作的進階混合式加密核心函式庫。它旨在提供一個經過實戰檢驗的藍圖，展示如何將業界領先的密碼學函式庫（**libsodium**, **OpenSSL**, **libcurl**）組合成一個穩健、可靠且易於使用的端對端加密解決方案。

我們的設計遵循以下核心安全原則：

*   **選擇經審查的現代密碼學：** 絕不自行開發加密演算法。僅使用受社群廣泛認可、能抵抗旁路攻擊的現代密碼學原語。
*   **深度防禦：** 安全性不依賴於任何單一層面。我們在記憶體管理、API 設計、協定流程等多個層面實施保護。
*   **安全預設與「故障關閉」策略：** 系統的預設行為必須是安全的。當面臨不確定狀態（例如，無法驗證憑證撤銷狀態）時，系統必須選擇失敗並終止操作（故障關閉），而不是繼續執行。
*   **最小化敏感資料暴露：** 嚴格控制私鑰等關鍵資料在記憶體中的生命週期、作用域和駐留時間，使其達到絕對必要的最小值。

## 2. 核心特性

*   **穩健的混合式加密模型：**
    *   **對稱式加密：** 基於 **XChaCha20-Poly1305** 提供 AEAD 串流加密（適用於大資料區塊）和一次性 AEAD 加密（適用於小資料區塊）。
    *   **非對稱式加密：** 使用 **X25519**（基於 Curve2519）對對稱會話金鑰進行金鑰封裝，確保只有預期的接收者可以解密。

*   **現代密碼學原語堆疊：**
    *   **金鑰派生：** 採用密碼雜湊競賽的優勝者 **Argon2id**，有效抵抗 GPU 和 ASIC 的破解嘗試。
    *   **數位簽章：** 利用 **Ed25519** 提供高速、高安全性的數位簽章能力。
    *   **金鑰統一：** 巧妙地利用了 Ed25519 金鑰可以安全轉換為 X25519 金鑰的特性，允許單一主金鑰對同時滿足簽章和加密的需求。

*   **完善的公開金鑰基礎設施 (PKI) 支援：**
    *   **憑證生命週期：** 支援產生符合 X.509 v3 標準的憑證簽署請求 (CSR)。
    *   **嚴格的憑證驗證：** 提供標準化的憑證驗證流程，包括信任鏈、有效期和主體匹配。
    *   **強制撤銷檢查 (OCSP)：** 內建嚴格的線上憑證狀態協定 (OCSP) 檢查，並採用「故障關閉」策略，如果無法確認憑證的良好狀態，操作將立即中止。

*   **堅若磐石的記憶體安全：**
    *   透過公共 API 暴露 `libsodium` 的安全記憶體函式，允許客戶端安全地處理敏感資料（如會話金鑰）。
    *   **[安全文件記錄]** 所有內部私鑰**及其他關鍵秘密（如金鑰種子、中繼雜湊值）**均儲存在鎖定記憶體中，**防止被作業系統交換至磁碟**，並在釋放前被安全清除。與第三方函式庫（如 OpenSSL）的資料邊界被精心管理。當敏感資料必須跨越到標準記憶體區域時（例如在 `generate_csr` 中傳遞種子給 OpenSSL），本函式庫採用深度防禦技術（如在使用後立即清理記憶體緩衝區）來緩解固有風險，這代表了在與非安全記憶體感知的函式庫互動時的最佳實踐。

*   **高品質的工程實踐：**
    *   **清晰的 API 邊界：** 提供單一的公共標頭檔 `hsc_kernel.h`，透過不透明指標封裝所有內部實作細節，實現高內聚、低耦合。
    *   **全面的測試套件：** 包含一套單元和整合測試，涵蓋核心密碼學、PKI 和進階 API 功能，確保程式碼的正確性和可靠性。
    *   **解耦的日誌系統：** 實作基於回呼的日誌機制，讓客戶端應用程式完全控制日誌訊息的顯示方式和位置，使函式庫適用於任何環境。
    *   **詳盡的文件與範例：** 提供詳細的 `README.md`，以及一個可直接執行的示範程式和一個功能強大的命令列工具。

## 3. 專案結構

專案採用清晰、分層的目錄結構來實現關注點分離。

```.
├── include/
│   └── hsc_kernel.h      # [核心] 唯一的公共API標頭檔
├── src/                  # 原始碼
│   ├── common/           # 通用內部模組 (安全記憶體, 日誌)
│   ├── core_crypto/      # 核心加密內部模組 (libsodium 封裝)
│   ├── pki/              # PKI 內部模組 (OpenSSL, libcurl 封裝)
│   ├── hsc_kernel.c      # [核心] 公共API的實作
│   ├── main.c            # API用法範例: 端對端示範程式
│   └── cli.c             # API用法範例: 功能強大的命令列工具
├── tests/                # 單元測試和測試工具
│   ├── test_*.c          # 各模組的單元測試
│   ├── test_api_integration.c # [新增] 進階API的端對端測試
│   ├── test_helpers.h/.c # 測試輔助函式 (CA產生, 簽章)
│   └── test_ca_util.c    # 獨立的測試CA工具的原始碼
├── Makefile              # 建置和任務管理腳本
└── README.md             # 本專案的文件
```

## 4. 快速入門

### 4.1 依賴環境

*   **建置工具:** `make`
*   **C 編譯器:** `gcc` 或 `clang` (支援 C11 和 `-Werror`)
*   **libsodium:** (`libsodium-dev`)
*   **OpenSSL:** 推薦 **v3.0** 或更高版本 (`libssl-dev`)
*   **libcurl:** (`libcurl4-openssl-dev`)

**在主流系統上的安裝:**

*   **Debian/Ubuntu:**
    ```bash
    sudo apt-get update
    sudo apt-get install build-essential libsodium-dev libssl-dev libcurl4-openssl-dev
    ```
*   **Fedora/RHEL/CentOS:**
    ```bash
    sudo dnf install gcc make libsodium-devel openssl-devel libcurl-devel
    ```
*   **macOS (使用 Homebrew):**
    ```bash
    brew install libsodium openssl@3 curl
    ```

### 4.2 編譯與測試

專案被設計為高度可移植，並避免了平台特定的硬編碼路徑，確保它能在所有支援的系統上正確建置和執行。

1.  **編譯所有目標 (函式庫, 示範程式, 命令列工具, 測試):**
    ```bash
    make all
    ```

2.  **執行全面的測試套件 (關鍵步驟):**
    ```bash
    make run-tests
    ```
    > **關於 OCSP 測試預期行為的重要說明**
    >
    > `test_pki_verification` 中的一個測試案例會故意驗證一個指向不存在的本地 OCSP 伺服器（`http://127.0.0.1:8888`）的憑證。網路請求將會失敗，此時 `hsc_verify_user_certificate` 函式**必須**返回 `-12` (即 `HSC_ERROR_CERT_REVOKED_OR_OCSP_FAILED` 的錯誤碼)。測試程式會斷言這個特定的傳回值。
    >
    > 這個「失敗」是**預期的、正確的行為**，因為它完美地證明了我們的「故障關閉」安全策略得到了正確實施：**如果因任何原因無法確認憑證的撤銷狀態，該憑證將被視為無效。**

3.  **執行示範程式:**
    ```bash
    ./bin/hsc_demo
    ```

4.  **探索命令列工具:**
    ```bash
    ./bin/hsc_cli
    ```

5.  **清理建置檔案:**
    ```bash
    make clean
    ```

## 5. 使用指南

### 5.1 作為命令列工具使用 (`hsc_cli` & `test_ca_util`)

本節提供了一個完整的、自包含的工作流程，展示了兩位使用者（Alice 和 Bob）如何使用提供的命令列工具進行安全的檔案交換。

**工具角色:**
*   `./bin/test_ca_util`: 一個輔助工具，用於模擬一個憑證頒發機構 (CA)，負責產生根憑證和簽署使用者憑證。
*   `./bin/hsc_cli`: 核心的客戶端工具，用於金鑰產生、CSR 建立、憑證驗證以及檔案的加解密。

**完整工作流程範例: Alice 加密一個檔案並安全地傳送給 Bob**

1.  **(設定) 建立一個測試憑證頒發機構 (CA):**
    *我們使用 `test_ca_util` 來產生一個根 CA 金鑰和一個自簽章憑證。*
    ```bash
    ./bin/test_ca_util gen-ca ca.key ca.pem
    ```

2.  **(Alice & Bob) 產生各自的主金鑰對:**
    ```bash
    ./bin/hsc_cli gen-keypair alice
    ./bin/hsc_cli gen-keypair bob
    ```
    *這將建立 `alice.key`, `alice.pub`, `bob.key`, 和 `bob.pub`。*

3.  **(Alice & Bob) 產生憑證簽署請求 (CSRs):**
    ```bash
    ./bin/hsc_cli gen-csr alice.key "alice@example.com"
    ./bin/hsc_cli gen-csr bob.key "bob@example.com"
    ```
    *這將建立 `alice.csr` 和 `bob.csr`。*

4.  **(CA) 簽署 CSR 以頒發憑證:**
    *CA 使用其私鑰 (`ca.key`) 和憑證 (`ca.pem`) 來簽署 CSR。*
    ```bash
    ./bin/test_ca_util sign alice.csr ca.key ca.pem alice.pem
    ./bin/test_ca_util sign bob.csr ca.key ca.pem bob.pem
    ```
    *現在 Alice 和 Bob 擁有了他們正式的憑證, `alice.pem` 和 `bob.pem`。*

5.  **(Alice) 在傳送前驗證 Bob 的憑證:**
    *Alice 使用受信任的 CA 憑證 (`ca.pem`) 來驗證 Bob 的身份。這是信任其憑證之前的關鍵一步。*
    ```bash
    ./bin/hsc_cli verify-cert bob.pem --ca ca.pem --user "bob@example.com"
    ```

6.  **(Alice) 為 Bob 加密一個檔案:**
    *Alice 現在有多種選擇:*

    **選項 A: 基於憑證並進行驗證 (安全預設 & 推薦)**
    > 這是標準的、安全的操作方式。工具**要求** Alice 提供 CA 憑證和預期的使用者名稱，以便在加密前對 Bob 的憑證執行完整、嚴格的驗證。
    ```bash
    echo "This is top secret information." > secret.txt
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key --ca ca.pem --user "bob@example.com"
    ```

    **選項 B: 基於憑證但不驗證 (危險 - 僅限專家)**
    > 如果 Alice 絕對確定憑證的真實性並希望跳過驗證，她必須明確使用 `--no-verify` 旗標。**不推薦這樣做。**
    ```bash
    # 請極度謹慎使用!
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key --no-verify
    ```

    **選項 C: 直接金鑰模式 (進階 - 用於預先信任的金鑰)**
    *如果 Alice 已經透過一個安全的、可信的管道獲得了 Bob 的公鑰 (`bob.pub`)，她可以直接對其加密，繞過所有憑證邏輯。*
    ```bash
    ./bin/hsc_cli encrypt secret.txt --recipient-pk-file bob.pub --from alice.key
    ```
    *所有選項都會建立 `secret.txt.hsc`。Alice 現在可以將 `secret.txt.hsc` 和她的憑證 `alice.pem` 傳送給 Bob。*

7.  **(Bob) 收到後解密檔案:**
    *Bob 使用他的私鑰 (`bob.key`) 來解密檔案。根據 Alice 的加密方式，他將需要 Alice 的憑證 (`alice.pem`) 或她的原始公鑰 (`alice.pub`)。*

    **如果 Alice 使用了選項 A 或 B (憑證):**
    ```bash
    ./bin/hsc_cli decrypt secret.txt.hsc --to bob.key --from alice.pem
    ```

    **如果 Alice 使用了選項 C (直接金鑰):**
    ```bash
    ./bin/hsc_cli decrypt secret.txt.hsc --to bob.key --sender-pk-file alice.pub
    ```    *兩個指令都會產生 `secret.txt.decrypted`。*
    ```bash
    cat secret.txt.decrypted
    ```

### 5.2 在您的專案中作為函式庫使用

`src/main.c` 是一個優秀的整合範例。典型的 API 呼叫流程如下：

1.  **全域初始化與日誌設定:** 在啟動時呼叫 `hsc_init()` 並註冊一個日誌回呼。
    ```c
    #include "hsc_kernel.h"
    #include <stdio.h>

    // 為您的應用程式定義一個簡單的日誌函式
    void my_app_logger(int level, const char* message) {
        // 範例: 將錯誤印到 stderr，資訊印到 stdout
        if (level >= 2) { // 2 = ERROR
            fprintf(stderr, "[HSC_LIB_ERROR] %s\n", message);
        } else {
            printf("[HSC_LIB_INFO] %s\n", message);
        }
    }

    int main() {
        if (hsc_init() != HSC_OK) {
            // 處理致命錯誤
        }
        // 向函式庫註冊您的日誌函式
        hsc_set_log_callback(my_app_logger);

        // ... 您的程式碼 ...
        hsc_cleanup();
        return 0;
    }
    ```

2.  **傳送方 (Alice) 加密資料:**
    ```c
    // 1. 產生一個一次性的會話金鑰
    unsigned char session_key[HSC_SESSION_KEY_BYTES];
    hsc_random_bytes(session_key, sizeof(session_key));

    // 2. 使用AEAD以會話金鑰加密資料 (適用於小資料)
    const char* message = "Secret message";
    // ... (加密邏輯同範例) ...

    // 3. 驗證接收者 (Bob) 的憑證
    if (hsc_verify_user_certificate(bob_cert_pem, ca_pem, "bob@example.com") != HSC_OK) {
        // 憑證無效，中止！函式庫將透過您的回呼記錄詳細資訊。
    }

    // 4. 從他的憑證中提取 Bob 的公鑰
    unsigned char bob_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    if (hsc_extract_public_key_from_cert(bob_cert_pem, bob_pk) != HSC_OK) {
        // 處理提取錯誤
    }

    // 5. 封裝會話金鑰
    // ... (封裝邏輯同範例) ...
    ```

3.  **接收方 (Bob) 解密資料:**
    *解密邏輯保持不變，但任何在解封裝或 AEAD 解密期間的內部錯誤現在都將透過您註冊的 `my_app_logger` 回呼報告，而不是直接污染 `stderr`。*

## 6. 深度剖析：技術架構

本專案的核心是混合式加密模型，它結合了非對稱和對稱密碼學的優點，以實現既安全又高效的資料傳輸。

**資料流與金鑰關係圖:**

```
傳送方 (ALICE)                                           接收方 (BOB)
========================================================================
[ 明文 ] ------> 產生 [ 會話金鑰 ]
                   |          |
(對稱式加密) <------'          '-> (非對稱式封裝) 使用: Bob的公鑰, Alice的私鑰
     |                                          |
[ 加密資料 ]                            [ 封裝後的會話金鑰 ]
     |                                          |
     '--------------------.  .------------------'
                          |  |
                          v  v
                       [ 資料包 ]
                          |
   ==================>  透過網路/檔案  =================>
                          |
                       [ 資料包 ]
                          |  |
           .--------------'  '----------------.
           |                                  |
   [ 封裝後的會話金鑰 ]                    [ 加密資料 ]
           |                                  |
           v                                  |
(非對稱式解封裝) 使用: Bob的私鑰, Alice的公鑰    |
           |                                  |
           v                                  |
  [ 恢復的會話金鑰 ] <-------------$----' (對稱式解密)
           |
           v
        [ 明文 ]
```

## 7. 進階設定：透過環境變數增強安全性

為了適應未來的硬體和安全需求而無需修改程式碼，本專案支援透過環境變數**增加**金鑰派生函式 (Argon2id) 的計算成本。

*   **`HSC_ARGON2_OPSLIMIT`**: 設定 Argon2id 的操作次數（計算輪數）。
*   **`HSC_ARGON2_MEMLIMIT`**: 以位元組為單位設定 Argon2id 的記憶體使用量。

**重要安全說明:** 此功能**只能用於增強安全參數**。如果環境變數中設定的值低於專案中內建的最低安全基準，程式將自動忽略這些不安全的值，並強制執行內建的最小值。

**用法範例:**

```bash
# 範例: 將操作限制增加到10，記憶體限制增加到512MB。
# 注意: HSC_ARGON2_MEMLIMIT 需要以位元組為單位的值。
# 512 * 1024 * 1024 = 536870912 位元組。
export HSC_ARGON2_OPSLIMIT=10
export HSC_ARGON2_MEMLIMIT=536870912

# 在設定了這些變數的 shell 中執行任何程式，都將自動使用這些更強的參數。
./bin/hsc_cli gen-keypair my_strong_key
```

## 8. 進階主題：加密模式比較

Oracipher Core 提供了兩種截然不同的混合式加密工作流程，每種都有不同的安全保證。選擇正確的模式至關重要。

### 基於憑證的工作流程 (預設 & 推薦)

*   **工作原理:** 使用 X.509 憑證將使用者身份（例如，`bob@example.com`）與其公鑰綁定。
*   **安全保證:**
    *   **身份驗證:** 以密碼學方式驗證公鑰確實屬於預期的接收者。
    *   **完整性:** 確保憑證未被篡改。
    *   **撤銷檢查:** 透過 OCSP 主動檢查憑證是否已被憑證頒發機構撤銷。
*   **使用時機:** 在傳送方和接收方沒有預先存在的高度安全管道來交換公鑰的任何情境。這是大多數基於網際網路的通訊的標準。

### 直接金鑰 (原始) 工作流程 (進階)

*   **工作原理:** 繞過所有 PKI 和憑證邏輯，直接對一個原始公鑰檔案進行加密。
*   **安全保證:**
    *   為加密資料本身提供了與憑證模式相同等級的**機密性**和**完整性**。
*   **安全權衡:**
    *   **無身份驗證:** 此模式**不會**驗證金鑰所有者的身份。使用者全權負責確保他們正在使用的公鑰的真實性。使用不正確或惡意的公鑰將導致資料為錯誤的一方加密。
*   **使用時機:** 僅在封閉系統或特定協定中使用，其中公鑰已透過獨立的、可信的帶外機制（例如，金鑰固化在安全裝置的韌體中，或親自驗證）交換和驗證。

## 9. 核心API參考 (`include/hsc_kernel.h`)

### 初始化與清理
| 函式 | 描述 |
| :--- | :--- |
| `int hsc_init()` | **(必須首先呼叫)** 初始化整個函式庫。 |
| `void hsc_cleanup()` | 在程式退出前呼叫以釋放全域資源。 |

### 金鑰管理
| 函式 | 描述 |
| :--- | :--- |
| `hsc_master_key_pair* hsc_generate_master_key_pair()` | 產生一個新的主金鑰對。 |
| `hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(...)` | 從檔案載入一個私鑰。 |
| `int hsc_save_master_key_pair(...)` | 將一個金鑰對儲存到檔案。 |
| `void hsc_free_master_key_pair(hsc_master_key_pair** kp)` | 安全地釋放一個主金鑰對。 |
| `int hsc_get_master_public_key(const hsc_master_key_pair* kp, ...)` | **[新增]** 從金鑰對控制代碼中提取原始公鑰。 |

### PKI & 憑證
| 函式 | 描述 |
| :--- | :--- |
| `int hsc_generate_csr(...)` | 產生 PEM 格式的憑證簽署請求 (CSR)。 |
| `int hsc_verify_user_certificate(...)` | **(核心)** 執行完整的憑證驗證 (信任鏈, 有效期, 主體, OCSP)。 |
| `int hsc_extract_public_key_from_cert(...)` | 從一個已驗證的憑證中提取公鑰。 |

### 金鑰封裝 (非對稱)
| 函式 | 描述 |
| :--- | :--- |
| `int hsc_encapsulate_session_key(...)` | 使用接收者的公鑰加密一個會話金鑰。 |
| `int hsc_decapsulate_session_key(...)` | 使用接收者的私鑰解密一個會話金鑰。 |

### 串流加密 (對稱, 適用於大檔案)
| 函式 | 描述 |
| :--- | :--- |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(...)` | 建立一個加密串流狀態物件。 |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(...)` | 建立一個解密串流狀態物件。 |
| `int hsc_crypto_stream_push(...)` | 在串流中加密一塊資料。 |
| `int hsc_crypto_stream_pull(...)` | 在串流中解密一塊資料。 |
| `void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state)` | 釋放串流狀態物件。 |
| `int hsc_hybrid_encrypt_stream_raw(...)` | 使用原始公鑰對檔案執行完整的混合式加密。 |
| `int hsc_hybrid_decrypt_stream_raw(...)` | 使用原始公鑰對檔案執行完整的混合式解密。 |

### 資料加密 (對稱, 適用於小資料)
| 函式 | 描述 |
| :--- | :--- |
| `int hsc_aead_encrypt(...)` | 使用 AEAD 對**一小塊資料**執行認證加密。 |
| `int hsc_aead_decrypt(...)` | 解密並驗證由 `hsc_aead_encrypt` 加密的資料。 |

### 安全記憶體
| 函式 | 描述 |
| :--- | :--- |
| `void* hsc_secure_alloc(size_t size)` | 配置一塊受保護的、不可交換的記憶體。 |
| `void hsc_secure_free(void* ptr)` | 安全地清除並釋放一塊受保護的記憶體。 |

### 日誌
| 函式 | 描述 |
| :--- | :--- |
| `void hsc_set_log_callback(hsc_log_callback callback)` | **[新增]** 註冊一個回呼函式來處理所有內部的函式庫日誌。 |

## 10. 貢獻

我們歡迎所有形式的貢獻！如果您發現錯誤、有功能建議或希望改進文件，請隨時提交 Pull Request 或建立 Issue。

## 11. 憑證說明

本專案使用 **X.509 v3** 憑證體系將公鑰與使用者身份（例如 `alice@example.com`）綁定，從而建立信任。憑證驗證過程包括**簽章鏈驗證**、**有效期檢查**、**主體驗證**和**撤銷狀態檢查 (OCSP)**，所有這些都在嚴格的「故障關閉」策略下進行。

## 12. 授權許可 - 雙重授權模式

本專案在**雙重授權**模型下分發：

### 1. GNU Affero General Public License v3.0 (AGPLv3)
適用於開源專案、學術研究和個人學習。它要求任何修改過的或透過網路提供服務的衍生作品也必須在 AGPLv3 下開放其完整原始碼。

### 2. 商業授權
任何閉源的商業應用程式、產品或服務都必須取得。如果您不希望受到 AGPLv3 開源條款的約束，則必須取得商業授權。

**要取得商業授權，請聯絡: `eldric520lol@gmail.com`**