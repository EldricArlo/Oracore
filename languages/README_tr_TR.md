<div align="center">
  <img src="./src/media/icon-256.png" alt="Oracipher Simgesi" width="128">
  <h1 style="border-bottom: none;">Oracipher Core</h1>

# Yüksek Güvenlikli Hibrit Şifreleme Çekirdek Kütüphanesi

| Derleme & Test | Lisans | Dil | Bağımlılıklar |
| :---: | :---: | :---: | :---: |
| ![Build Status](https://img.shields.io/badge/tests-passing-brightgreen) | ![License](https://img.shields.io/badge/license-Dual--Licensed-blue) | ![Language](https://img.shields.io/badge/language-C11-purple) | ![Libsodium](https://img.shields.io/badge/libsodium-v1.0.18+-brightgreen) ![OpenSSL](https://img.shields.io/badge/OpenSSL-v3.0+-0075A8) ![Libcurl](https://img.shields.io/badge/libcurl-v7.68+-E5522D) |

</div>

---

### **İçindekiler**
1.  [Proje Vizyonu ve Temel İlkeler](#1-proje-vizyonu-ve-temel-ilkeler)
2.  [Temel Özellikler](#2-temel-özellikler)
3.  [Proje Yapısı](#3-proje-yapısı)
4.  [Hızlı Başlangıç](#4-hızlı-başlangıç)
    *   [4.1 Bağımlılıklar](#41-bağımlılıklar)
    *   [4.2 Derleme ve Test Etme](#42-derleme-ve-test-etme)
5.  [Kullanım Kılavuzu](#5-kullanım-kılavuzu)
    *   [5.1 Komut Satırı Aracı Olarak Kullanım (`hsc_cli` & `test_ca_util`)](#51-komut-satırı-aracı-olarak-kullanım-hsc_cli--test_ca_util)
    *   [5.2 Projenizde Kütüphane Olarak Kullanım](#52-projenizde-kütüphane-olarak-kullanım)
6.  [Derinlemesine Bakış: Teknik Mimari](#6-derinlemesine-bakış-teknik-mimari)
7.  [Gelişmiş Yapılandırma: Ortam Değişkenleri ile Güvenliği Artırma](#7-gelişmiş-yapılandırma-ortam-değişkenleri-ile-güvenliği-artırma)
8.  [İleri Düzey Konu: Şifreleme Modlarının Karşılaştırılması](#8-ileri-düzey-konu-şifreleme-modlarının-karşılaştırılması)
9.  [Çekirdek API Referansı (`include/hsc_kernel.h`)](#9-çekirdek-api-referansı-includehsc_kernelh)
10. [Katkıda Bulunma](#10-katkıda-bulunma)
11. [Sertifika Notları](#11-sertifika-notları)
12. [Lisans - İkili Lisanslama Modeli](#12-lisans---ikili-lisanslama-modeli)

---

## 1. Proje Vizyonu ve Temel İlkeler

Bu proje, C11 standardında uygulanmış, güvenlik odaklı, gelişmiş bir hibrit şifreleme çekirdek kütüphanesidir. Sektör lideri kriptografi kütüphanelerini (**libsodium**, **OpenSSL**, **libcurl**) sağlam, güvenilir ve kullanımı kolay bir uçtan uca şifreleme çözümünde birleştirmek için savaşta test edilmiş bir şablon sağlamayı amaçlamaktadır.

Tasarımımız aşağıdaki temel güvenlik ilkelerine uyar:

*   **Denetlenmiş, Modern Kriptografiyi Seçin:** Asla kendi kriptomuzu geliştirmeyiz. Yalnızca topluluk tarafından geniş çapta tanınan ve yan kanal saldırılarına dayanıklı modern kriptografik ilkelleri kullanırız.
*   **Derinlemesine Savunma:** Güvenlik tek bir katmana dayanmaz. Bellek yönetimi, API tasarımı ve protokol akışı dahil olmak üzere birden çok düzeyde koruma uygularız.
*   **Güvenli Varsayılanlar ve "Hata Durumunda Kapat" Politikası:** Sistemin varsayılan davranışı güvenli olmalıdır. Belirsiz bir durumla karşılaşıldığında (örneğin, sertifika iptal durumunu doğrulayamama), sistem devam etmek yerine başarısız olmayı ve işlemi sonlandırmayı (hata durumunda kapat) seçmelidir.
*   **Hassas Veri Maruziyetini En Aza İndirin:** Özel anahtarlar gibi kritik verilerin bellekteki yaşam döngüsünü, kapsamını ve kalma süresini kesinlikle kontrol eder, bunları mutlak gerekli minimumda tutarız.

## 2. Temel Özellikler

*   **Sağlam Hibrit Şifreleme Modeli:**
    *   **Simetrik Şifreleme:** **XChaCha20-Poly1305** tabanlı AEAD akış şifrelemesi (büyük veri blokları için) ve tek seferlik AEAD şifrelemesi (küçük veri blokları için) sağlar.
    *   **Asimetrik Şifreleme:** Simetrik oturum anahtarını sarmak için bir Anahtar Kapsülleme Mekanizması (KEM) olarak **X25519** (Curve2519 tabanlı) kullanır ve yalnızca hedeflenen alıcının şifresini çözebilmesini sağlar.

*   **Modern Kriptografik İlkel Yığını:**
    *   **Anahtar Türetme:** GPU ve ASIC kırma girişimlerine etkili bir şekilde direnmek için Parola Karma Yarışması'nın galibi olan **Argon2id**'yi kullanır.
    *   **Dijital İmzalar:** Yüksek hızlı, yüksek güvenlikli dijital imza yetenekleri için **Ed25519**'dan yararlanır.
    *   **Birleşik Anahtarlar:** Ed25519 anahtarlarının güvenli bir şekilde X25519 anahtarlarına dönüştürülebilmesi özelliğini akıllıca kullanarak, tek bir ana anahtar çiftinin hem imzalama hem de şifreleme ihtiyaçlarını karşılamasına olanak tanır.

*   **Kapsamlı Açık Anahtar Altyapısı (PKI) Desteği:**
    *   **Sertifika Yaşam Döngüsü:** X.509 v3 uyumlu Sertifika İmzalama Talepleri (CSR'ler) oluşturulmasını destekler.
    *   **Katı Sertifika Doğrulaması:** Güven zinciri, geçerlilik süresi ve konu eşleşmesi dahil olmak üzere standartlaştırılmış bir sertifika doğrulama süreci sağlar.
    *   **Zorunlu İptal Kontrolü (OCSP):** "Hata durumunda kapat" politikasıyla yerleşik, katı Çevrimiçi Sertifika Durum Protokolü (OCSP) kontrolleri içerir. Sertifikanın iyi durumu teyit edilemezse, işlem derhal iptal edilir.

*   **Kaya Gibi Sağlam Bellek Güvenliği:**
    *   `libsodium`'un güvenli bellek işlevlerini genel API aracılığıyla sunarak, istemcilerin hassas verileri (oturum anahtarları gibi) güvenli bir şekilde işlemesine olanak tanır.
    *   **[Güvenli Bir Şekilde Belgelenmiştir]** Tüm dahili özel anahtarlar **ve diğer kritik sırlar (örneğin, anahtar tohumları, ara karma değerleri)** kilitli bellekte saklanır, **işletim sistemi tarafından diske takas edilmelerini önler** ve serbest bırakılmadan önce güvenli bir şekilde sıfırlanır. Üçüncü taraf kütüphanelerle (OpenSSL gibi) sınırlar dikkatlice yönetilir. Hassas verilerin standart bellek bölgelerine geçmesi gerektiğinde (örneğin, `generate_csr` içinde OpenSSL'e bir tohum geçerken), bu kütüphane doğal riskleri azaltmak için derinlemesine savunma teknikleri (kullanımdan hemen sonra bellek arabelleklerini temizlemek gibi) kullanır ve bu, güvenli bellek bilincine sahip olmayan kütüphanelerle etkileşimde bulunurken en iyi uygulama yaklaşımını temsil eder.

*   **Yüksek Kaliteli Mühendislik Uygulamaları:**
    *   **Temiz API Sınırı:** Opak işaretçiler kullanarak tüm dahili uygulama ayrıntılarını kapsülleyen tek bir genel başlık dosyası, `hsc_kernel.h` sağlar, böylece yüksek uyum ve düşük bağlılık elde edilir.
    *   **Kapsamlı Test Paketi:** Kodun doğruluğunu ve güvenilirliğini sağlamak için çekirdek kriptografi, PKI ve üst düzey API işlevlerini kapsayan bir birim ve entegrasyon testleri paketi içerir.
    *   **Ayrıştırılmış Günlükleme Sistemi:** Geri arama tabanlı bir günlükleme mekanizması uygular, istemci uygulamasına günlük mesajlarının nasıl ve nerede görüntüleneceği konusunda tam kontrol sağlar ve kütüphaneyi her ortama uygun hale getirir.
    *   **Kapsamlı Belgeler ve Örnekler:** Ayrıntılı bir `README.md` ile birlikte çalışmaya hazır bir demo programı ve güçlü bir komut satırı aracı sağlar.

## 3. Proje Yapısı

Proje, endişelerin ayrılmasını sağlamak için temiz, katmanlı bir dizin yapısı kullanır.

```.
├── include/
│   └── hsc_kernel.h      # [Çekirdek] Tek genel API başlığı
├── src/                  # Kaynak Kodu
│   ├── common/           # Ortak dahili modüller (güvenli bellek, günlükleme)
│   ├── core_crypto/      # Çekirdek kripto dahili modülleri (libsodium sarmalayıcıları)
│   ├── pki/              # PKI dahili modülleri (OpenSSL, libcurl sarmalayıcıları)
│   ├── hsc_kernel.c      # [Çekirdek] Genel API'nin uygulanması
│   ├── main.c            # API Kullanım Örneği: Uçtan uca demo programı
│   └── cli.c             # API Kullanım Örneği: Güçlü komut satırı aracı
├── tests/                # Birim testleri ve test yardımcı programları
│   ├── test_*.c          # Çeşitli modüller için birim testleri
│   ├── test_api_integration.c # [Yeni] Üst düzey API'ler için uçtan uca testler
│   ├── test_helpers.h/.c # Test yardımcı işlevleri (CA oluşturma, imzalama)
│   └── test_ca_util.c    # Bağımsız test CA yardımcı programının kaynak kodu
├── Makefile              # Derleme ve görev yönetimi betiği
└── README.md             # Bu projenin belgeleri
```

## 4. Hızlı Başlangıç

### 4.1 Bağımlılıklar

*   **Derleme Araçları:** `make`
*   **C Derleyicisi:** `gcc` veya `clang` (C11 ve `-Werror` desteği ile)
*   **libsodium:** (`libsodium-dev`)
*   **OpenSSL:** **v3.0** veya daha yenisi önerilir (`libssl-dev`)
*   **libcurl:** (`libcurl4-openssl-dev`)

**Büyük Sistemlerde Kurulum:**

*   **Debian/Ubuntu:**
    ```bash
    sudo apt-get update
    sudo apt-get install build-essential libsodium-dev libssl-dev libcurl4-openssl-dev
    ```
*   **Fedora/RHEL/CentOS:**
    ```bash
    sudo dnf install gcc make libsodium-devel openssl-devel libcurl-devel
    ```
*   **macOS (Homebrew kullanarak):**
    ```bash
    brew install libsodium openssl@3 curl
    ```

### 4.2 Derleme ve Test Etme

Proje, yüksek düzeyde taşınabilir olacak şekilde tasarlanmıştır ve platforma özgü sabit kodlanmış yollardan kaçınarak, desteklenen tüm sistemlerde doğru şekilde derlenip çalışmasını sağlar.

1.  **Tüm Hedefleri Derle (kütüphane, demo, CLI, testler):**
    ```bash
    make all
    ```

2.  **Kapsamlı Test Paketini Çalıştır (Kritik Adım):**
    ```bash
    make run-tests
    ```
    > **Beklenen OCSP Test Davranışı Hakkında Önemli Not**
    >
    > `test_pki_verification` içindeki bir test durumu, kasıtlı olarak var olmayan bir yerel OCSP sunucusuna (`http://127.0.0.1:8888`) işaret eden bir sertifikayı doğrular. Ağ isteği başarısız olacak ve bu noktada `hsc_verify_user_certificate` işlevi **mutlaka** `-12` (`HSC_ERROR_CERT_REVOKED_OR_OCSP_FAILED` için hata kodu) döndürmelidir. Test programı bu belirli dönüş değerini doğrular.
    >
    > Bu "başarısızlık", **beklenen ve doğru davranıştır**, çünkü "hata durumunda kapat" güvenlik politikamızın doğru bir şekilde uygulandığını mükemmel bir şekilde gösterir: **bir sertifikanın iptal durumu herhangi bir nedenle teyit edilemezse, geçersiz olarak kabul edilir.**

3.  **Demo Programını Çalıştır:**
    ```bash
    ./bin/hsc_demo
    ```

4.  **Komut Satırı Aracını Keşfet:**
    ```bash
    ./bin/hsc_cli
    ```

5.  **Derleme Dosyalarını Temizle:**
    ```bash
    make clean
    ```

## 5. Kullanım Kılavuzu

### 5.1 Komut Satırı Aracı Olarak Kullanım (`hsc_cli` & `test_ca_util`)

Bu bölüm, Alice ve Bob adlı iki kullanıcının sağlanan komut satırı araçlarını kullanarak güvenli bir dosya alışverişini nasıl gerçekleştirebileceğini gösteren eksiksiz, kendi kendine yeten bir iş akışı sunar.

**Araç Rolleri:**
*   `./bin/test_ca_util`: Bir Sertifika Yetkilisini (CA) simüle eden, kök sertifika oluşturmaktan ve kullanıcı sertifikalarını imzalamaktan sorumlu bir yardımcı program.
*   `./bin/hsc_cli`: Anahtar oluşturma, CSR oluşturma, sertifika doğrulama ve dosya şifreleme/şifre çözme için temel istemci aracı.

**Tam İş Akışı Örneği: Alice Bir Dosyayı Şifreler ve Güvenli Bir Şekilde Bob'a Gönderir**

1.  **(Kurulum) Bir Test Sertifika Yetkilisi (CA) Oluşturun:**
    *Bir kök CA anahtarı ve kendinden imzalı bir sertifika oluşturmak için `test_ca_util`'i kullanırız.*
    ```bash
    ./bin/test_ca_util gen-ca ca.key ca.pem
    ```

2.  **(Alice ve Bob) Ana Anahtar Çiftlerini Oluşturun:**
    ```bash
    ./bin/hsc_cli gen-keypair alice
    ./bin/hsc_cli gen-keypair bob
    ```
    *Bu, `alice.key`, `alice.pub`, `bob.key` ve `bob.pub` dosyalarını oluşturur.*

3.  **(Alice ve Bob) Sertifika İmzalama Talepleri (CSR'ler) Oluşturun:**
    ```bash
    ./bin/hsc_cli gen-csr alice.key "alice@example.com"
    ./bin/hsc_cli gen-csr bob.key "bob@example.com"
    ```
    *Bu, `alice.csr` ve `bob.csr` dosyalarını oluşturur.*

4.  **(CA) Sertifikaları Vermek İçin CSR'leri İmzalayın:**
    *CA, CSR'leri imzalamak için özel anahtarını (`ca.key`) ve sertifikasını (`ca.pem`) kullanır.*
    ```bash
    ./bin/test_ca_util sign alice.csr ca.key ca.pem alice.pem
    ./bin/test_ca_util sign bob.csr ca.key ca.pem bob.pem
    ```
    *Alice ve Bob'un artık resmi sertifikaları olan `alice.pem` ve `bob.pem` var.*

5.  **(Alice) Göndermeden Önce Bob'un Sertifikasını Doğrular:**
    *Alice, Bob'un kimliğini doğrulamak için güvenilen CA sertifikasını (`ca.pem`) kullanır. Bu, sertifikasına güvenmeden önce kritik bir adımdır.*
    ```bash
    ./bin/hsc_cli verify-cert bob.pem --ca ca.pem --user "bob@example.com"
    ```

6.  **(Alice) Bob İçin Bir Dosyayı Şifreler:**
    *Alice'in şimdi birkaç seçeneği var:*

    **Seçenek A: Doğrulamalı Sertifika Tabanlı (Güvenli Varsayılan ve Önerilen)**
    > Bu, standart, güvenli çalışma şeklidir. Araç, Alice'in şifrelemeden önce Bob'un sertifikasının tam ve katı bir doğrulamasını gerçekleştirmesi için CA sertifikasını ve beklenen kullanıcı adını sağlamasını **gerektirir**.
    ```bash
    echo "This is top secret information." > secret.txt
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key --ca ca.pem --user "bob@example.com"
    ```

    **Seçenek B: Doğrulamasız Sertifika Tabanlı (Tehlikeli - Yalnızca Uzman Kullanımı)**
    > Alice sertifikanın gerçekliğinden kesinlikle eminse ve doğrulamayı atlamak istiyorsa, açıkça `--no-verify` bayrağını kullanmalıdır. **Bu önerilmez.**
    ```bash
    # Son derece dikkatli kullanın!
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key --no-verify
    ```

    **Seçenek C: Doğrudan Anahtar Modu (Gelişmiş - Önceden Güvenilen Anahtarlar İçin)**
    *Alice, Bob'un genel anahtarını (`bob.pub`) güvenli, güvenilir bir kanal aracılığıyla zaten elde ettiyse, tüm sertifika mantığını atlayarak doğrudan ona şifreleme yapabilir.*
    ```bash
    ./bin/hsc_cli encrypt secret.txt --recipient-pk-file bob.pub --from alice.key
    ```
    *Tüm seçenekler `secret.txt.hsc` oluşturur. Alice şimdi `secret.txt.hsc`'yi ve sertifikası `alice.pem`'i Bob'a gönderebilir.*

7.  **(Bob) Alındığında Dosyanın Şifresini Çözer:**
    *Bob, dosyanın şifresini çözmek için özel anahtarını (`bob.key`) kullanır. Alice'in nasıl şifrelediğine bağlı olarak, ya onun sertifikasına (`alice.pem`) ya da ham genel anahtarına (`alice.pub`) ihtiyaç duyacaktır.*

    **Alice Seçenek A veya B'yi (Sertifika) Kullandıysa:**
    ```bash
    ./bin/hsc_cli decrypt secret.txt.hsc --to bob.key --from alice.pem
    ```

    **Alice Seçenek C'yi (Doğrudan Anahtar) Kullandıysa:**
    ```bash
    ./bin/hsc_cli decrypt secret.txt.hsc --to bob.key --sender-pk-file alice.pub
    ```
    *Her iki komut da `secret.txt.decrypted` üretecektir.*
    ```bash
    cat secret.txt.decrypted
    ```

### 5.2 Projenizde Kütüphane Olarak Kullanım

`src/main.c` mükemmel bir entegrasyon örneği olarak hizmet eder. Tipik bir API çağrı akışı aşağıdaki gibidir:

1.  **Genel Başlatma ve Günlük Kurulumu:** Başlangıçta `hsc_init()` çağırın ve bir günlük geri araması kaydedin.
    ```c
    #include "hsc_kernel.h"
    #include <stdio.h>

    // Uygulamanız için basit bir günlükleme işlevi tanımlayın
    void my_app_logger(int level, const char* message) {
        // Örnek: Hataları stderr'e, bilgileri stdout'a yazdır
        if (level >= 2) { // 2 = ERROR
            fprintf(stderr, "[HSC_LIB_ERROR] %s\n", message);
        } else {
            printf("[HSC_LIB_INFO] %s\n", message);
        }
    }

    int main() {
        if (hsc_init() != HSC_OK) {
            // Önemli hatayı işle
        }
        // Günlükleme işlevinizi kütüphaneye kaydedin
        hsc_set_log_callback(my_app_logger);

        // ... Kodunuz ...
        hsc_cleanup();
        return 0;
    }
    ```

2.  **Gönderen (Alice) Veriyi Şifreler:**
    ```c
    // 1. Tek kullanımlık bir oturum anahtarı oluşturun
    unsigned char session_key[HSC_SESSION_KEY_BYTES];
    hsc_random_bytes(session_key, sizeof(session_key));

    // 2. AEAD kullanarak veriyi oturum anahtarıyla şifreleyin (küçük veriler için)
    const char* message = "Secret message";
    // ... (şifreleme mantığı örnektekiyle aynıdır) ...

    // 3. Alıcının (Bob'un) sertifikasını doğrulayın
    if (hsc_verify_user_certificate(bob_cert_pem, ca_pem, "bob@example.com") != HSC_OK) {
        // Sertifika geçersiz, iptal et! Kütüphane ayrıntıları geri aramanız aracılığıyla günlüğe kaydedecektir.
    }

    // 4. Bob'un genel anahtarını sertifikasından çıkarın
    unsigned char bob_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    if (hsc_extract_public_key_from_cert(bob_cert_pem, bob_pk) != HSC_OK) {
        // Çıkarma hatasını işle
    }

    // 5. Oturum anahtarını kapsülleyin
    // ... (kapsülleme mantığı örnektekiyle aynıdır) ...
    ```

3.  **Alıcı (Bob) Verinin Şifresini Çözer:**
    *Şifre çözme mantığı aynı kalır, ancak kapsül açma veya AEAD şifre çözme sırasındaki herhangi bir dahili hata artık doğrudan `stderr`'i kirletmek yerine kayıtlı `my_app_logger` geri aramanız aracılığıyla bildirilecektir.*

## 6. Derinlemesine Bakış: Teknik Mimari

Bu projenin özü, hem güvenli hem de verimli veri aktarımı sağlamak için asimetrik ve simetrik kriptografinin avantajlarını birleştiren bir hibrit şifreleme modelidir.

**Veri Akışı ve Anahtar İlişki Diyagramı:**

```
GÖNDEREN (ALICE)                                         ALICI (BOB)
========================================================================
[ Düz Metin ] --> Oluştur [ Oturum Anahtarı ]
                     |           |
(Simetrik Şifrele) <-'           '-> (Asimetrik Kapsülle) kullanarak: Bob'un Genel Anahtarı, Alice'in Özel Anahtarı
      |                                             |
[ Şifreli Veri ]                      [ Kapsüllenmiş Oturum Anahtarı ]
      |                                             |
      '---------------------.   .-------------------'
                            |   |
                            v   v
                        [ Veri Paketi ]
                            |
    ==================>  Ağ/Dosya Üzerinden  =================>
                            |
                        [ Veri Paketi ]
                            |   |
            .---------------'   '-----------------.
            |                                     |
[ Kapsüllenmiş Oturum Anahtarı ]          [ Şifreli Veri ]
            |                                     |
            v                                     |
(Asimetrik Kapsül Aç) kullanarak: Bob'un Özel Anahtarı, Alice'in Genel Anahtarı
            |                                     |
            v                                     |
       [ Kurtarılmış Oturum Anahtarı ] <-$--------' (Simetrik Şifre Çöz)
            |
            v
       [ Düz Metin ]
```

## 7. Gelişmiş Yapılandırma: Ortam Değişkenleri ile Güvenliği Artırma

Gelecekteki donanım ve güvenlik ihtiyaçlarına kod değişikliği yapmadan uyum sağlamak için, bu proje ortam değişkenleri aracılığıyla anahtar türetme işlevinin (Argon2id) hesaplama maliyetini **artırmayı** destekler.

*   **`HSC_ARGON2_OPSLIMIT`**: Argon2id için işlem sayısını (hesaplama turları) ayarlar.
*   **`HSC_ARGON2_MEMLIMIT`**: Argon2id için bellek kullanımını bayt cinsinden ayarlar.

**Önemli Güvenlik Notu:** Bu özellik **yalnızca güvenlik parametrelerini güçlendirmek için kullanılabilir**. Ortam değişkenlerinde ayarlanan değerler projeye yerleşik minimum güvenlik temellerinden daha düşükse, program güvensiz değerleri otomatik olarak yok sayar ve yerleşik minimumları zorunlu kılar.

**Kullanım Örneği:**

```bash
# Örnek: İşlem limitini 10'a ve bellek limitini 512MB'a çıkarın.
# Not: HSC_ARGON2_MEMLIMIT değeri bayt cinsinden gerektirir.
# 512 * 1024 * 1024 = 536870912 bayt.
export HSC_ARGON2_OPSLIMIT=10
export HSC_ARGON2_MEMLIMIT=536870912

# Bu değişkenlerin ayarlandığı bir kabukta çalıştırılan herhangi bir program, otomatik olarak bu daha güçlü parametreleri kullanacaktır.
./bin/hsc_cli gen-keypair my_strong_key
```

## 8. İleri Düzey Konu: Şifreleme Modlarının Karşılaştırılması

Oracipher Core, her biri farklı güvenlik garantilerine sahip iki ayrı hibrit şifreleme iş akışı sunar. Doğru olanı seçmek kritik öneme sahiptir.

### Sertifika Tabanlı İş Akışı (Varsayılan ve Önerilen)

*   **Nasıl Çalışır:** Bir kullanıcının kimliğini (örneğin, `bob@example.com`) genel anahtarına bağlamak için X.509 sertifikalarını kullanır.
*   **Güvenlik Garantileri:**
    *   **Kimlik Doğrulama:** Genel anahtarın gerçekten hedeflenen alıcıya ait olduğunu kriptografik olarak doğrular.
    *   **Bütünlük:** Sertifikanın kurcalanmadığını garanti eder.
    *   **İptal Kontrolü:** Sertifikanın veren yetkili tarafından iptal edilip edilmediğini OCSP aracılığıyla aktif olarak kontrol eder.
*   **Ne Zaman Kullanılır:** Gönderen ve alıcının genel anahtarları değiş tokuş etmek için önceden var olan, yüksek güvenlikli bir kanalı olmadığı herhangi bir senaryoda. Bu, çoğu internet tabanlı iletişim için standarttır.

### Doğrudan Anahtar (Ham) İş Akışı (Gelişmiş)

*   **Nasıl Çalışır:** Tüm PKI ve sertifika mantığını atlar, doğrudan ham bir genel anahtar dosyasına şifreleme yapar.
*   **Güvenlik Garantileri:**
    *   Şifrelenmiş verinin kendisi için sertifika moduyla aynı düzeyde **gizlilik** ve **bütünlük** sağlar.
*   **Güvenlik Ödünleri:**
    *   **Kimlik Doğrulama Yok:** Bu mod, anahtarın sahibinin kimliğini **doğrulamaz**. Kullandıkları genel anahtarın gerçekliğini sağlamak yalnızca kullanıcının sorumluluğundadır. Yanlış veya kötü niyetli bir genel anahtar kullanmak, verilerin yanlış taraf için şifrelenmesine neden olacaktır.
*   **Ne Zaman Kullanılır:** Yalnızca kapalı sistemlerde veya genel anahtarların bağımsız, güvenilir bir bant dışı mekanizma (örneğin, anahtarların güvenli bir cihazın donanım yazılımına gömülmesi veya bizzat doğrulanması) aracılığıyla değiş tokuş edildiği ve doğrulandığı belirli protokollerde kullanılır.

## 9. Çekirdek API Referansı (`include/hsc_kernel.h`)

### Başlatma ve Temizleme
| İşlev | Açıklama |
| :--- | :--- |
| `int hsc_init()` | **(Önce çağrılmalıdır)** Tüm kütüphaneyi başlatır. |
| `void hsc_cleanup()` | Program çıkışından önce genel kaynakları serbest bırakmak için çağırın. |

### Anahtar Yönetimi
| İşlev | Açıklama |
| :--- | :--- |
| `hsc_master_key_pair* hsc_generate_master_key_pair()` | Yeni bir ana anahtar çifti oluşturur. |
| `hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(...)` | Bir dosyadan özel bir anahtar yükler. |
| `int hsc_save_master_key_pair(...)` | Bir anahtar çiftini dosyalara kaydeder. |
| `void hsc_free_master_key_pair(hsc_master_key_pair** kp)` | Bir ana anahtar çiftini güvenli bir şekilde serbest bırakır. |
| `int hsc_get_master_public_key(const hsc_master_key_pair* kp, ...)` | **[Yeni]** Ham genel anahtarı bir anahtar çifti tanıtıcısından çıkarır. |

### PKI ve Sertifikalar
| İşlev | Açıklama |
| :--- | :--- |
| `int hsc_generate_csr(...)` | PEM biçimli bir Sertifika İmzalama Talebi (CSR) oluşturur. |
| `int hsc_verify_user_certificate(...)` | **(Çekirdek)** Tam sertifika doğrulaması gerçekleştirir (zincir, geçerlilik, konu, OCSP). |
| `int hsc_extract_public_key_from_cert(...)` | Doğrulanmış bir sertifikadan bir genel anahtar çıkarır. |

### Anahtar Kapsülleme (Asimetrik)
| İşlev | Açıklama |
| :--- | :--- |
| `int hsc_encapsulate_session_key(...)` | Alıcının genel anahtarını kullanarak bir oturum anahtarını şifreler. |
| `int hsc_decapsulate_session_key(...)` | Alıcının özel anahtarını kullanarak bir oturum anahtarının şifresini çözer. |

### Akış Şifrelemesi (Simetrik, büyük dosyalar için)
| İşlev | Açıklama |
| :--- | :--- |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(...)` | Bir şifreleme akışı durum nesnesi oluşturur. |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(...)` | Bir şifre çözme akışı durum nesnesi oluşturur. |
| `int hsc_crypto_stream_push(...)` | Bir akışta bir veri parçasını şifreler. |
| `int hsc_crypto_stream_pull(...)` | Bir akışta bir veri parçasının şifresini çözer. |
| `void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state)` | Bir akış durumu nesnesini serbest bırakır. |
| `int hsc_hybrid_encrypt_stream_raw(...)` | Ham bir genel anahtar kullanarak bir dosyada tam hibrit şifreleme gerçekleştirir. |
| `int hsc_hybrid_decrypt_stream_raw(...)` | Ham bir genel anahtar kullanarak bir dosyada tam hibrit şifre çözme gerçekleştirir. |

### Veri Şifrelemesi (Simetrik, küçük veriler için)
| İşlev | Açıklama |
| :--- | :--- |
| `int hsc_aead_encrypt(...)` | AEAD kullanarak **küçük bir veri parçası** üzerinde kimliği doğrulanmış şifreleme gerçekleştirir. |
| `int hsc_aead_decrypt(...)` | `hsc_aead_encrypt` tarafından şifrelenen verinin şifresini çözer ve doğrular. |

### Güvenli Bellek
| İşlev | Açıklama |
| :--- | :--- |
| `void* hsc_secure_alloc(size_t size)` | Korumalı, takas edilemez bir bellek bloğu ayırır. |
| `void hsc_secure_free(void* ptr)` | Korumalı bir bellek bloğunu güvenli bir şekilde sıfırlar ve serbest bırakır. |

### Günlükleme
| İşlev | Açıklama |
| :--- | :--- |
| `void hsc_set_log_callback(hsc_log_callback callback)` | **[Yeni]** Tüm dahili kütüphane günlüklerini işlemek için bir geri arama işlevi kaydeder. |

## 10. Katkıda Bulunma

Her türlü katkıyı memnuniyetle karşılıyoruz! Bir hata bulursanız, bir özellik öneriniz varsa veya belgeleri iyileştirmek isterseniz, lütfen bir Çekme İsteği (Pull Request) göndermekten veya bir Sorun (Issue) oluşturmaktan çekinmeyin.

## 11. Sertifika Notları

Bu proje, genel anahtarları kullanıcı kimliklerine (örneğin, `alice@example.com`) bağlamak için bir **X.509 v3** sertifika sistemi kullanır ve böylece güven oluşturur. Sertifika doğrulama süreci, **imza zinciri doğrulaması**, **geçerlilik süresi kontrolleri**, **konu kimliği doğrulaması** ve **iptal durumu kontrolünü (OCSP)** içerir, hepsi katı bir "hata durumunda kapat" politikası altında.

## 12. Lisans - İkili Lisanslama Modeli

Bu proje **ikili lisans** modeli altında dağıtılmaktadır:

### 1. GNU Affero Genel Kamu Lisansı v3.0 (AGPLv3)
Bu lisans, açık kaynaklı projeler, akademik araştırmalar ve kişisel çalışmalar için uygundur. Değiştirilmiş veya bir ağ üzerinden hizmet olarak sunulan herhangi bir türev çalışmanın da tam kaynak kodunun AGPLv3 altında kullanıma sunulmasını gerektirir.

### 2. Ticari Lisans
Herhangi bir kapalı kaynaklı ticari uygulama, ürün veya hizmet için bir ticari lisans alınmalıdır. AGPLv3'ün açık kaynak koşullarına bağlı kalmak istemiyorsanız, bir ticari lisans almanız gerekir.

**Ticari bir lisans almak için lütfen iletişime geçin: `eldric520lol@gmail.com`**