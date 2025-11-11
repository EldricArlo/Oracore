<div align="center">
  <img src="../src/media/icon-256.png" alt="Oracipher Simgesi" width="128">
  <h1 style="border-bottom: none;">Oracipher Core</h1>

# Yüksek Güvenlikli Hibrit Şifreleme Çekirdek Kütüphanesi

| Derleme | Lisans | Dil | Bağımlılıklar |
| :---: | :---: | :---: | :---: |
| ![Build Status](https://img.shields.io/badge/build-passing-brightgreen) | ![License](https://img.shields.io/badge/license-Dual--Licensed-blue) | ![Language](https://img.shields.io/badge/language-C11-purple) | ![Libsodium](https://img.shields.io/badge/libsodium-v1.0.18+-brightgreen) ![OpenSSL](https://img.shields.io/badge/OpenSSL-v3.0+-0075A8) ![Libcurl](https://img.shields.io/badge/libcurl-v7.68+-E5522D) |

</div>

## 1. 😎 Proje Vizyonu ve Temel İlkeler

Bu proje, C11 standardı kullanılarak geliştirilmiş, güvenliğe odaklanmış, üst düzey bir hibrit şifreleme çekirdek kütüphanesidir. Sektör lideri kriptografi kütüphanelerini (**libsodium**, **OpenSSL**, **libcurl**) bir araya getirerek sağlam, güvenilir ve kullanımı kolay bir uçtan uca şifreleme çözümünün nasıl oluşturulacağını gösteren, savaşta test edilmiş bir şablon sunmayı amaçlamaktadır.

Tasarımımız aşağıdaki temel güvenlik ilkelerini takip eder:

*   🥸 **İncelenmiş Modern Kriptografi Seçimi:** Asla kendi şifreleme algoritmalarınızı uygulamayın. Sadece topluluk tarafından tanınan, yan kanal saldırılarına dayanıklı modern kriptografik ilkelleri kullanın.
*   🤠 **Derinlemesine Savunma:** Güvenlik tek bir katmana bağlı değildir. Bellek yönetiminden API tasarımına ve protokol akışına kadar her katmanda savunma mekanizmaları kurulmuştur.
*   🙃 **Güvenli Varsayılanlar ve "Hata Durumunda Kapatma" (Fail-Closed):** Sistemin varsayılan davranışı güvenli olmalıdır. Belirsiz bir durumla karşılaşıldığında (örneğin bir sertifikanın iptal durumunun doğrulanamaması), sistem çalışmaya devam etmek yerine başarısız olmayı seçmeli ve işlemi sonlandırmalıdır (Fail-Closed).
*   🫥 **Hassas Veri Maruziyetini En Aza İndirme:** Özel anahtarlar gibi kritik verilerin yaşam döngüsü, kapsamı ve bellekte kalma süresi, kesinlikle gerekli olan en düşük seviyede sıkı bir şekilde kontrol edilmelidir.

## 2. 🥲 Temel Özellikler

*   😮 **Sağlam Hibrit Şifreleme Modeli:**
    *   **Simetrik Şifreleme:** Büyük veri blokları için **XChaCha20-Poly1305** tabanlı AEAD akış şifrelemesi ve küçük veri blokları için tek seferlik AEAD şifrelemesi sunar.
    *   **Asimetrik Şifreleme:** Simetrik oturum anahtarını kapsüllemek için **X25519** (Curve25519 tabanlı) kullanır, böylece sadece hedeflenen alıcının şifreyi çözebilmesini sağlar.

*   🫨 **Modern Kriptografik İlkel Yığını:**
    *   **Anahtar Türetme:** Parola Özetleme Yarışması'nın galibi olan ve GPU ve ASIC tabanlı kırılmalara karşı etkili bir şekilde direnen **Argon2id**'yi benimser.
    *   **Dijital İmza:** Yüksek hız ve yüksek güvenlikli dijital imza yetenekleri sunan **Ed25519**'u kullanır.
    *   **Anahtar Birleştirme:** Ed25519 anahtarlarının güvenli bir şekilde X25519 anahtarlarına dönüştürülebilmesi özelliğinden akıllıca yararlanarak, tek bir ana anahtar çifti ile hem imzalama hem de şifreleme ihtiyaçlarını karşılar.

*   😏 **Kapsamlı Açık Anahtar Altyapısı (PKI) Desteği:**
    *   **Sertifika Yaşam Döngüsü:** X.509 v3 standardına uygun Sertifika İmzalama İsteği (CSR) oluşturmayı destekler.
    *   **Katı Sertifika Doğrulaması:** Güven zinciri, geçerlilik süresi ve konu eşleşmesini içeren standartlaştırılmış bir sertifika doğrulama süreci sunar.
    *   **Zorunlu İptal Kontrolü (OCSP):** Dahili olarak katı bir Çevrimiçi Sertifika Durum Protokolü (OCSP) kontrolü barındırır ve sertifikanın iyi durumda olduğu teyit edilemediğinde işlemi derhal durduran "hata durumunda kapatma" politikasını benimser.

*   🧐 **Sarsılmaz Bellek Güvenliği:**
    *   `libsodium`'un güvenli bellek özelliklerini genel bir API aracılığıyla sunarak, istemcilerin hassas verileri (oturum anahtarları gibi) güvenli bir şekilde işlemesine olanak tanır.
    *   Tüm dahili özel anahtarlar, **işletim sistemi tarafından diske takas edilmelerini önlemek için** kilitli bellekte saklanır ve serbest bırakılmadan önce güvenli bir şekilde silinir.

*   😵‍💫 **Yüksek Kaliteli Mühendislik Uygulamaları:**
    *   **Net API Sınırları:** Tüm dahili uygulama ayrıntılarını opak işaretçiler (opaque pointers) kullanarak kapsülleyen ve yüksek bütünlük ile düşük bağımlılık sağlayan birleşik bir genel başlık dosyası `hsc_kernel.h` sunar.
    *   **Birim Testlerinden Geçirilmiş:** Çekirdek şifreleme ve PKI işlevlerini kapsayan bir dizi birim testi içerir, bu da kodun doğruluğunu ve güvenilirliğini sağlar.
    *   **Kapsamlı Dokümantasyon ve Örnekler:** Ayrıntılı bir `README.md` dosyasının yanı sıra doğrudan çalıştırılabilir bir demo programı ve bir komut satırı aracı sunar.

## 3. 🤓 Proje Yapısı

Proje, sorumlulukların ayrılması ilkesini gerçekleştirmek için net ve katmanlı bir dizin yapısı kullanır.

```
.
├── include/
│   └── hsc_kernel.h      # [ÇEKİRDEK] Tek genel API başlık dosyası
├── src/                  # Kaynak kodu
│   ├── common/           # Ortak dahili modüller (güvenli bellek, güvenlik standartları)
│   ├── core_crypto/      # Çekirdek şifreleme dahili modülleri (libsodium sarmalayıcısı)
│   ├── pki/              # PKI dahili modülleri (OpenSSL, libcurl sarmalayıcıları)
│   ├── hsc_kernel.c      # [ÇEKİRDEK] Genel API'nin uygulanması
│   ├── main.c            # API kullanım örneği: Uçtan uca akış demo programı
│   └── cli.c             # API kullanım örneği: Güçlü komut satırı aracı
├── tests/                # Birim testleri
│   ├── test_*.c          # Çeşitli modüller için birim testleri
│   └── test_helpers.h/.c # Test yardımcı fonksiyonları
├── Makefile              # Derleme ve görev yönetimi betiği
└── README.md             # Bu projenin açıklama belgesi
```

## 4. 🤥 Hızlı Başlangıç

### 4.1. Ortam Bağımlılıkları

*   **Derleme Araçları:** `make`
*   **C Derleyicisi:** `gcc` veya `clang` (C11 standardını desteklemeli)
*   **libsodium:** (`libsodium-dev`)
*   **OpenSSL:** **v3.0** veya üstü önerilir (`libssl-dev`)
*   **libcurl:** (`libcurl4-openssl-dev`)

**Debian/Ubuntu üzerinde tek komutla kurulum:**
```bash
sudo apt-get update
sudo apt-get install build-essential libsodium-dev libssl-dev libcurl4-openssl-dev
```

### 4.2. Derleme ve Test Etme

1.  **Tüm hedefleri derleyin (kütüphane, demo, CLI, testler):**
    ```bash
    make all
    ```

2.  **Birim testlerini çalıştırın (kritik adım):**
    ```bash
    make run-tests
    ```
    > 😝 **OCSP Testinin Beklenen Davranışı Hakkında Not**
    >
    > `test_pki_verification` içindeki bir test senaryosu, doğrulama için kasıtlı olarak geçersiz bir OCSP sunucusuna işaret eden bir sertifika kullanacaktır. Ağ isteği kaçınılmaz olarak başarısız olacağından, `hsc_verify_user_certificate` fonksiyonu iptal durumu kontrolünün başarısız olduğunu belirtmek için **-4** döndürmelidir. Test kodu, geri dönüş değerinin gerçekten -4 olduğunu doğrulayarak "hata durumunda kapatma" güvenlik mekanizmamızın düzgün çalıştığını kanıtlar.

3.  **Demo programını çalıştırın:**
    ```bash
    ./bin/hsc_demo
    ```

4.  **Komut satırı aracını çalıştırın:**
    ```bash
    ./bin/hsc_cli --help
    ```

5.  **Derleme dosyalarını temizleyin:**
    ```bash
    make clean
    ```

## 5. ☺️ Kullanım Kılavuzu

### 5.1. Komut Satırı Aracı Olarak (`hsc_cli`)

`hsc_cli`, tüm temel şifreleme ve PKI işlemlerini gerçekleştirmek için kullanılan, **esnek parametre sırasını destekleyen** tam özellikli bir komut satırı aracıdır.

**Tam İş Akışı Örneği: Alice bir dosyayı şifreler ve Bob'a güvenli bir şekilde gönderir**

1.  **😒 (Her iki taraf) Ana anahtar çiftlerini oluşturur:**
    ```bash
    ./bin/hsc_cli gen-keypair alice
    ./bin/hsc_cli gen-keypair bob
    ```

2.  **☺️ (Her iki taraf) CSR oluşturur ve sertifika alır:** (Burada bir CA'nın `alice.pem` ve `bob.pem` dosyalarını zaten yayınladığı varsayılmaktadır)
    ```bash
    ./bin/hsc_cli gen-csr alice.key "alice@example.com"
    # (alice.csr dosyasını CA'ya göndererek alice.pem'i alın)
    ```

3.  **🤨 (Alice) Bob'un sertifikasını doğrular:** (`ca.pem`'in güvenilir kök CA sertifikası olduğu varsayılır)
    ```bash
    ./bin/hsc_cli verify-cert bob.pem --ca ca.pem --user "bob@example.com"
    ```
    > **İpucu:** Değer alan seçenekler (`--ca` ve `--user` gibi) artık herhangi bir sırada listelenebilir.

4.  **😑 (Alice) Bob için bir dosyayı şifreler:**
    ```bash
    echo "This is top secret information." > secret.txt
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key
    ```    Artık Alice `secret.hsc` dosyasını ve kendi sertifikası olan `alice.pem`'i Bob'a gönderebilir.

5.  **😉 (Bob) Dosyayı aldıktan sonra şifresini çözer:**
    ```bash
    # Bob ayrıca --from ve --to'nun sırasını değiştirebilir
    ./bin/hsc_cli decrypt secret.hsc --to bob.key --from alice.pem
    cat secret.decrypted
    ```

### 5.2. Projenize Kütüphane Olarak Entegre Etme

`src/main.c` dosyası mükemmel bir entegrasyon örneğidir. Tipik API çağrı akışı aşağıdadır:

1.  **Global Başlatma:** Program başlangıcında `hsc_init()` fonksiyonunu çağırın.
    ```c
    #include "hsc_kernel.h"
    
    int main() {
        if (hsc_init() != 0) {
            // Ölümcül hatayı işle
        }
        // ... kodunuz ...
        hsc_cleanup();
        return 0;
    }
    ```

2.  **Gönderici (Alice) Veriyi Şifreler:**
    ```c
    // 1. Tek kullanımlık bir oturum anahtarı oluştur
    unsigned char session_key[HSC_SESSION_KEY_BYTES];
    randombytes_buf(session_key, sizeof(session_key));

    // 2. Oturum anahtarını kullanarak AEAD ile veriyi şifrele (küçük veriler için uygun)
    const char* message = "Secret message";
    size_t enc_buf_size = strlen(message) + HSC_AEAD_NONCE_BYTES + HSC_AEAD_TAG_BYTES;
    unsigned char* encrypted_data = malloc(enc_buf_size);
    unsigned long long encrypted_data_len;
    hsc_aead_encrypt(encrypted_data, &encrypted_data_len, 
                     (const unsigned char*)message, strlen(message), session_key);

    // 3. Alıcının (Bob) sertifikasını doğrula
    if (hsc_verify_user_certificate(bob_cert_pem, ca_pem, "bob@example.com") != 0) {
        // Geçersiz sertifika, iptal et!
    }

    // 4. Bob'un sertifikasından açık anahtarını çıkar
    unsigned char bob_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    hsc_extract_public_key_from_cert(bob_cert_pem, bob_pk);

    // 5. Bob'un açık anahtarını ve Alice'in özel anahtarını kullanarak oturum anahtarını kapsülle
    // (alice_kp'nin yüklenmiş bir hsc_master_key_pair* olduğu varsayılır)
    unsigned char encapsulated_key[...]; size_t encapsulated_key_len;
    hsc_encapsulate_session_key(encapsulated_key, &encapsulated_key_len, 
                                session_key, sizeof(session_key),
                                bob_pk, alice_kp);
    
    // 6. encrypted_data ve encapsulated_key'i Bob'a gönder
    ```

3.  **Alıcı (Bob) Veriyi Çözer:**
    ```c
    // 1. Göndericinin (Alice) sertifikasından açık anahtarını çıkar
    unsigned char alice_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    hsc_extract_public_key_from_cert(alice_cert_pem, alice_pk);
    
    // 2. Alice'in açık anahtarını ve Bob'un kendi özel anahtarını kullanarak oturum anahtarını de-kapsülle
    // (bob_kp'nin yüklenmiş bir hsc_master_key_pair* olduğu varsayılır)
    unsigned char* dec_session_key = hsc_secure_alloc(HSC_SESSION_KEY_BYTES);
    if (hsc_decapsulate_session_key(dec_session_key, encapsulated_key, enc_key_len,
                                    alice_pk, bob_kp) != 0) {
        // De-kapsülleme başarısız!
    }

    // 3. Geri kazanılan oturum anahtarını kullanarak veriyi çöz
    unsigned char final_message[...]; unsigned long long final_len;
    if (hsc_aead_decrypt(final_message, &final_len,
                         encrypted_data, encrypted_data_len, dec_session_key) != 0) {
        // Çözme başarısız! Veri tahrif edilmiş
    }

    // 4. Kullandıktan sonra oturum anahtarını güvenli bir şekilde serbest bırak
    hsc_secure_free(dec_session_key);
    ```

## 6. 😶 Teknik Mimarinin Derinlemesine Analizi

Bu projenin çekirdeği, hem güvenli hem de verimli veri aktarımı sağlamak için asimetrik ve simetrik şifrelemenin avantajlarını birleştiren Hibrit Şifreleme modelidir.

**Veri Akışı ve Anahtar İlişki Şeması:**

```
GÖNDERİCİ (ALICE)                                        ALICI (BOB)
========================================================================
[ Orijinal Veri ] -> Oluşturur [Oturum Anahtarı]
                     |        |
(Simetrik Şifreleme) <---'        '-> (Asimetrik Kapsülleme) Kullanarak: Bob'un Açık Anahtarı, Alice'in Özel Anahtarı
        |                                      |
[Şifrelenmiş Veri]                    [Kapsüllenmiş Oturum Anahtarı]
        |                                      |
        '----------------. .------------------'
                         | |
                         v v
                     [İletim Paketi]
                          |
      ==================> | Ağ/Dosya Aktarımı =================>
                          |
                     [İletim Paketi]
                         | |
              .----------' '-------------.
              |                          |
[Kapsüllenmiş Oturum Anahtarı]      [Şifrelenmiş Veri]
              |                          |
              v                          |
(Asimetrik De-kapsülleme) Kullanarak: Bob'un Özel Anahtarı, Alice'in Açık Anahtarı |
              |                          |
              v                          |
         [Geri Kazanılan Oturum Anahtarı]<-$----' (Simetrik Çözme)
              |
              v
         [ Orijinal Veri ]
```

## 7. 😄 Gelişmiş Yapılandırma: Ortam Değişkenleriyle Güvenliği Artırma

Kodu değiştirmeden gelecekteki daha güçlü donanım ve güvenlik gereksinimlerine uyum sağlamak için, bu proje ortam değişkenleri aracılığıyla anahtar türetme fonksiyonunun (Argon2id) hesaplama gücünü **artırmayı** destekler.

*   **`HSC_ARGON2_OPSLIMIT`**: Argon2id için işlem (hesaplama) turu sayısını ayarlar.
*   **`HSC_ARGON2_MEMLIMIT`**: Argon2id için bellek kullanımını (bayt cinsinden) ayarlar.

**Önemli Güvenlik Notu:** Bu özellik **sadece güvenlik parametrelerini artırmak için kullanılabilir**. Ortam değişkenlerinde ayarlanan değerler projeye dahil edilmiş minimum güvenlik taban çizgisinden daha düşükse, program bu güvensiz değerleri otomatik olarak yok sayar ve yerleşik minimum değerleri kullanmaya zorlar.

** Yeni Kullanım Örneği:**

```bash
# Örnek: İşlem sınırını 10'a ve bellek sınırını 512MB'a yükseltin.
# Not: HSC_ARGON2_MEMLIMIT'in bayt cinsinden olması gerekir.
# 512 * 1024 * 1024 = 536870912 bayt.
export HSC_ARGON2_OPSLIMIT=10
export HSC_ARGON2_MEMLIMIT=536870912

# Programı, ortam değişkenlerinin ayarlandığı bir kabukta çalıştırın.
# Otomatik olarak bu daha güçlü parametreleri kullanacaktır.
./bin/hsc_cli gen-keypair my_strong_key
```

## 8. 😀 API Çekirdek Referansı (`include/hsc_kernel.h`)

### Başlatma ve Temizleme
| Fonksiyon | Açıklama |
| :--- | :--- |
| `int hsc_init()` | **(İlk olarak çağrılmalıdır)** Tüm kütüphaneyi başlatır. |
| `void hsc_cleanup()` | Global kaynakları serbest bırakmak için programdan çıkmadan önce çağrılır. |

### Anahtar Yönetimi
| Fonksiyon | Açıklama |
| :--- | :--- |
| `hsc_master_key_pair* hsc_generate_master_key_pair()` | Yepyeni bir ana anahtar çifti oluşturur. |
| `hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(...)` | Bir dosyadan özel bir anahtar yükler. |
| `int hsc_save_master_key_pair(...)` | Bir anahtar çiftini bir dosyaya kaydeder. |
| `void hsc_free_master_key_pair(hsc_master_key_pair** kp)` | Bir ana anahtar çiftini güvenli bir şekilde serbest bırakır. |

### PKI ve Sertifikalar
| Fonksiyon | Açıklama |
| :--- | :--- |
| `int hsc_generate_csr(...)` | PEM formatında bir Sertifika İmzalama İsteği (CSR) oluşturur. |
| `int hsc_verify_user_certificate(...)` | **(Merkezi)** Tam sertifika doğrulamasını gerçekleştirir (zincir, geçerlilik, konu, OCSP). |
| `int hsc_extract_public_key_from_cert(...)` | Doğrulanmış bir sertifikadan bir açık anahtar çıkarır. |

### Anahtar Kapsülleme (Asimetrik)
| Fonksiyon | Açıklama |
| :--- | :--- |
| `int hsc_encapsulate_session_key(...)` | Alıcının açık anahtarını kullanarak bir oturum anahtarını şifreler. |
| `int hsc_decapsulate_session_key(...)` | Alıcının özel anahtarını kullanarak bir oturum anahtarının şifresini çözer. |

### Veri Şifreleme (Simetrik)
| Fonksiyon | Açıklama |
| :--- | :--- |
| `int hsc_aead_encrypt(...)` | AEAD kullanarak **küçük bir veri bloğunu** kimliği doğrulanmış olarak şifreler. |
| `int hsc_aead_decrypt(...)` | `hsc_aead_encrypt` tarafından şifrelenmiş veriyi çözer ve doğrular. |

### Akış Şifreleme (Simetrik, büyük dosyalar için)
| Fonksiyon | Açıklama |
| :--- | :--- |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(...)` | Bir şifreleme akışı durum nesnesi oluşturur. |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(...)` | Bir şifre çözme akışı durum nesnesi oluşturur. |
| `int hsc_crypto_stream_push(...)` | Akıştaki bir veri bloğunu şifreler. |
| `int hsc_crypto_stream_pull(...)` | Akıştaki bir veri bloğunun şifresini çözer. |
| `void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state)` | Akış durumu nesnesini serbest bırakır. |

### Güvenli Bellek
| Fonksiyon | Açıklama |
| :--- | :--- |
| `void* hsc_secure_alloc(size_t size)` | Korunmuş ve takas edilemez bir bellek bloğu ayırır. |
| `void hsc_secure_free(void* ptr)` | Korunan belleği güvenli bir şekilde siler ve serbest bırakır. |


## 9. 🥳 Katkıda Bulunma

Her türlü katkıya açığız! Bir hata bulursanız, bir özellik öneriniz varsa veya dokümantasyonu iyileştirmek isterseniz, lütfen bir Pull Request göndermekten veya bir Issue oluşturmaktan çekinmeyin.

## 10. 🥺 Sertifika Açıklaması

Bu proje, bir açık anahtarı bir kullanıcı kimliğine (örneğin `alice@example.com`) bağlamak ve böylece güven oluşturmak için **X.509 v3** sertifika sistemini kullanır. Sertifika doğrulama süreci, **imza zinciri doğrulaması**, **geçerlilik kontrolü**, **konu kimliği doğrulaması** ve **iptal durumu kontrolünü (OCSP)** içerir ve katı bir "hata durumunda kapatma" politikasını benimser.

## 11. 🥸 Lisans - İkili Lisans Modeli

Bu proje **İkili Lisans (Dual-License)** modelini benimser:

### 1. GNU Affero General Public License v3.0 (AGPLv3)
Açık kaynaklı projeler, akademik araştırmalar ve kişisel öğrenim için uygundur. Değiştirilmiş veya bir ağ üzerinden hizmet olarak sunulan herhangi bir türev çalışmanın da tam kaynak kodunu AGPLv3 altında açmasını gerektirir.

### 2. Ticari Lisans
Herhangi bir kapalı kaynaklı ticari uygulama, ürün veya hizmet için uygundur. AGPLv3'ün açık kaynak şartlarına bağlı kalmak istemiyorsanız, bir ticari lisans almanız gerekir.

**Ticari bir lisans almak için lütfen iletişime geçin: `eldric520lol@gmail.com`**