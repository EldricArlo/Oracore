<div align="center">
  <img src="../src/media/icon-256.png" alt="Oracipher Icon" width="128">
  <h1 style="border-bottom: none;">Oracipher Core</h1>

# Biblioteca de Kernel de Criptografia Híbrida de Alta Segurança

| Build | Licença | Idioma | Dependências |
| :---: | :---: | :---: | :---: |
| ![Build Status](https://img.shields.io/badge/build-passing-brightgreen) | ![License](https://img.shields.io/badge/license-Dual--Licensed-blue) | ![Language](https://img.shields.io/badge/language-C11-purple) | ![Libsodium](https://img.shields.io/badge/libsodium-v1.0.18+-brightgreen) ![OpenSSL](https://img.shields.io/badge/OpenSSL-v3.0+-0075A8) ![Libcurl](https://img.shields.io/badge/libcurl-v7.68+-E5522D) |

</div>

## 1. 😎 Visão do Projeto e Princípios Fundamentais

Este projeto é uma biblioteca de kernel de criptografia híbrida avançada, implementada no padrão C11 e focada em segurança. Seu objetivo é fornecer um modelo comprovado em batalha que demonstra como combinar bibliotecas criptográficas líderes da indústria (**libsodium**, **OpenSSL**, **libcurl**) em uma solução de criptografia de ponta a ponta robusta, confiável e fácil de usar.

Nosso design segue os seguintes princípios de segurança fundamentais:

*   🥸 **Escolher Criptografia Moderna e Auditada:** Nunca implemente algoritmos de criptografia por conta própria. Use apenas primitivas criptográficas modernas, reconhecidas pela comunidade e resistentes a ataques de canal lateral.
*   🤠 **Defesa em Profundidade:** A segurança não depende de uma única camada. A defesa é construída em múltiplos níveis, desde o gerenciamento de memória e design da API até o fluxo do protocolo.
*   🙃 **Padrões Seguros e "Fail-Closed":** O comportamento padrão do sistema deve ser seguro. Ao encontrar um estado incerto (como a incapacidade de verificar o status de revogação de um certificado), o sistema deve optar por falhar e encerrar a operação (Fail-Closed), em vez de continuar a execução.
*   🫥 **Minimizar a Exposição de Dados Sensíveis:** O ciclo de vida, o escopo e o tempo de permanência em memória de dados críticos, como chaves privadas, devem ser estritamente controlados ao mínimo absoluto necessário.

## 2. 🥲 Principais Características

*   😮 **Modelo de Criptografia Híbrida Robusto:**
    *   **Criptografia Simétrica:** Fornece criptografia de fluxo AEAD baseada em **XChaCha20-Poly1305** para grandes blocos de dados e criptografia AEAD de uso único para pequenos blocos de dados.
    *   **Criptografia Assimétrica:** Usa **X25519** (baseado em Curve25519) para encapsulamento de chave da chave de sessão simétrica, garantindo que apenas o destinatário pretendido possa descriptografá-la.

*   🫨 **Pilha de Primitivas Criptográficas Modernas:**
    *   **Derivação de Chave:** Adota **Argon2id**, o vencedor da Competição de Hash de Senhas, que resiste eficazmente a ataques de GPU e ASIC.
    *   **Assinatura Digital:** Utiliza **Ed25519**, oferecendo capacidade de assinatura digital de alta velocidade e alta segurança.
    *   **Unificação de Chaves:** Utiliza inteligentemente a característica de que chaves Ed25519 podem ser convertidas com segurança em chaves X25519, permitindo que um único par de chaves mestre atenda tanto às necessidades de assinatura quanto de criptografia.

*   😏 **Suporte Abrangente à Infraestrutura de Chave Pública (PKI):**
    *   **Ciclo de Vida do Certificado:** Suporta a geração de Solicitações de Assinatura de Certificado (CSR) em conformidade com o padrão X.509 v3.
    *   **Verificação Rigorosa de Certificados:** Oferece um processo de verificação de certificados padronizado, incluindo cadeia de confiança, período de validade e correspondência de assunto.
    *   **Verificação Obrigatória de Revogação (OCSP):** Verificação rigorosa incorporada do Protocolo de Status de Certificado Online (OCSP) com uma política de "fail-closed", interrompendo imediatamente a operação se o bom estado do certificado não puder ser confirmado.

*   🧐 **Segurança de Memória Sólida:**
    *   Expõe as funcionalidades de memória segura da `libsodium` através de uma API pública, permitindo que os clientes manipulem dados sensíveis (como chaves de sessão) com segurança.
    *   Todas as chaves privadas internas são armazenadas em memória bloqueada, **impedindo que sejam trocadas para o disco pelo sistema operacional**, e são zeradas de forma segura antes de serem liberadas.

*   😵‍💫 **Práticas de Engenharia de Alta Qualidade:**
    *   **Limites de API Claros:** Fornece um único arquivo de cabeçalho público, `hsc_kernel.h`, que usa ponteiros opacos para encapsular todos os detalhes de implementação interna, alcançando alta coesão e baixo acoplamento.
    *   **Testado Unitariamente:** Inclui um conjunto de testes de unidade que cobrem as principais funcionalidades de criptografia e PKI, garantindo a correção e a confiabilidade do código.
    *   **Documentação e Exemplos Completos:** Oferece um `README.md` detalhado, bem como um programa de demonstração e uma ferramenta de linha de comando prontos para executar.

## 3. 🤓 Estrutura do Projeto

O projeto adota uma estrutura de diretórios clara e em camadas para alcançar a separação de preocupações.

```
.
├── include/
│   └── hsc_kernel.h      # [CORE] O único arquivo de cabeçalho da API pública
├── src/                  # Código-fonte
│   ├── common/           # Módulos internos comuns (memória segura, especificações de segurança)
│   ├── core_crypto/      # Módulos internos de criptografia (wrapper da libsodium)
│   ├── pki/              # Módulos internos de PKI (wrappers de OpenSSL, libcurl)
│   ├── hsc_kernel.c      # [CORE] Implementação da API pública
│   ├── main.c            # Exemplo de uso da API: Programa de demonstração de fluxo ponta a ponta
│   └── cli.c             # Exemplo de uso da API: Ferramenta de linha de comando poderosa
├── tests/                # Testes de unidade
│   ├── test_*.c          # Testes de unidade para vários módulos
│   └── test_helpers.h/.c # Funções auxiliares de teste
├── Makefile              # Script de construção e gerenciamento de tarefas
└── README.md             # Documentação deste projeto
```

## 4. 🤥 Guia de Início Rápido

### 4.1. Dependências do Ambiente

*   **Ferramentas de Construção:** `make`
*   **Compilador C:** `gcc` ou `clang` (com suporte ao padrão C11)
*   **libsodium:** (`libsodium-dev`)
*   **OpenSSL:** Recomendado **v3.0** ou superior (`libssl-dev`)
*   **libcurl:** (`libcurl4-openssl-dev`)

**Instalação com um único comando no Debian/Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install build-essential libsodium-dev libssl-dev libcurl4-openssl-dev
```

### 4.2. Compilação e Teste

1.  **Compilar todos os alvos (biblioteca, demonstração, CLI, testes):**
    ```bash
    make all
    ```

2.  **Executar os testes de unidade (passo crucial):**
    ```bash
    make run-tests
    ```
    > 😝 **Nota sobre o comportamento esperado do teste OCSP**
    >
    > Um caso de teste em `test_pki_verification` usará intencionalmente um certificado que aponta para um servidor OCSP inválido para verificação. Como a solicitação de rede inevitavelmente falhará, a função `hsc_verify_user_certificate` **deve** retornar `-4` para indicar uma falha na verificação do status de revogação. O código de teste afirmará que o valor de retorno é de fato `-4`, provando assim que nosso mecanismo de segurança "fail-closed" está funcionando corretamente.

3.  **Executar o programa de demonstração:**
    ```bash
    ./bin/hsc_demo
    ```

4.  **Executar a ferramenta de linha de comando:**
    ```bash
    ./bin/hsc_cli --help
    ```

5.  **Limpar os arquivos de construção:**
    ```bash
    make clean
    ```

## 5. ☺️ Guia de Uso

### 5.1. Como Ferramenta de Linha de Comando (`hsc_cli`)

`hsc_cli` é uma ferramenta de linha de comando completa, **que suporta uma ordem de parâmetros flexível**, para realizar todas as operações principais de criptografia e PKI.

**Exemplo de fluxo de trabalho completo: Alice criptografa um arquivo e o envia com segurança para Bob**

1.  **😒 (Ambas as partes) Gerar pares de chaves mestras:**
    ```bash
    ./bin/hsc_cli gen-keypair alice
    ./bin/hsc_cli gen-keypair bob
    ```

2.  **☺️ (Ambas as partes) Gerar CSR e obter certificados:** (Aqui, supõe-se que uma CA já emitiu `alice.pem` e `bob.pem`)
    ```bash
    ./bin/hsc_cli gen-csr alice.key "alice@example.com"
    # (Envie alice.csr para a CA para obter alice.pem)
    ```

3.  **🤨 (Alice) Verificar o certificado de Bob:** (Supondo que `ca.pem` seja o certificado da CA raiz confiável)
    ```bash
    ./bin/hsc_cli verify-cert bob.pem --ca ca.pem --user "bob@example.com"
    ```
    > **Dica:** Opções com valores (como `--ca` e `--user`) agora podem ser listadas em qualquer ordem.

4.  **😑 (Alice) Criptografar um arquivo para Bob:**
    ```bash
    echo "This is top secret information." > secret.txt
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key
    ```
    Agora Alice pode enviar `secret.hsc` e seu próprio certificado `alice.pem` para Bob.

5.  **😉 (Bob) Descriptografar o arquivo após recebê-lo:**
    ```bash
    # Bob também pode trocar a ordem de --from e --to
    ./bin/hsc_cli decrypt secret.hsc --to bob.key --from alice.pem
    cat secret.decrypted
    ```

### 5.2. Integrando como uma Biblioteca em seu Projeto

O arquivo `src/main.c` é um excelente exemplo de integração. A seguir, o fluxo de chamada de API típico:

1.  **Inicialização Global:** Na inicialização do programa, chame `hsc_init()`.
    ```c
    #include "hsc_kernel.h"
    
    int main() {
        if (hsc_init() != 0) {
            // Lidar com erro fatal
        }
        // ... seu código ...
        hsc_cleanup();
        return 0;
    }
    ```

2.  **Remetente (Alice) Criptografando Dados:**
    ```c
    // 1. Gerar uma chave de sessão de uso único
    unsigned char session_key[HSC_SESSION_KEY_BYTES];
    randombytes_buf(session_key, sizeof(session_key));

    // 2. Criptografar dados com a chave de sessão usando AEAD (adequado para pequenos dados)
    const char* message = "Secret message";
    size_t enc_buf_size = strlen(message) + HSC_AEAD_NONCE_BYTES + HSC_AEAD_TAG_BYTES;
    unsigned char* encrypted_data = malloc(enc_buf_size);
    unsigned long long encrypted_data_len;
    hsc_aead_encrypt(encrypted_data, &encrypted_data_len, 
                     (const unsigned char*)message, strlen(message), session_key);

    // 3. Verificar o certificado do destinatário (Bob)
    if (hsc_verify_user_certificate(bob_cert_pem, ca_pem, "bob@example.com") != 0) {
        // Certificado inválido, aborte!
    }

    // 4. Extrair a chave pública de Bob de seu certificado
    unsigned char bob_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    hsc_extract_public_key_from_cert(bob_cert_pem, bob_pk);

    // 5. Encapsular a chave de sessão usando a chave pública de Bob e a chave privada de Alice
    // (Supondo que alice_kp seja um hsc_master_key_pair* carregado)
    unsigned char encapsulated_key[...]; size_t encapsulated_key_len;
    hsc_encapsulate_session_key(encapsulated_key, &encapsulated_key_len, 
                                session_key, sizeof(session_key),
                                bob_pk, alice_kp);
    
    // 6. Enviar encrypted_data e encapsulated_key para Bob
    ```

3.  **Destinatário (Bob) Descriptografando Dados:**
    ```c
    // 1. Extrair a chave pública do remetente (Alice) de seu certificado
    unsigned char alice_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    hsc_extract_public_key_from_cert(alice_cert_pem, alice_pk);
    
    // 2. Desencapsular a chave de sessão usando a chave pública de Alice e a chave privada de Bob
    // (Supondo que bob_kp seja um hsc_master_key_pair* carregado)
    unsigned char* dec_session_key = hsc_secure_alloc(HSC_SESSION_KEY_BYTES);
    if (hsc_decapsulate_session_key(dec_session_key, encapsulated_key, enc_key_len,
                                    alice_pk, bob_kp) != 0) {
        // Falha no desencapsulamento!
    }

    // 3. Descriptografar os dados usando a chave de sessão recuperada
    unsigned char final_message[...]; unsigned long long final_len;
    if (hsc_aead_decrypt(final_message, &final_len,
                         encrypted_data, encrypted_data_len, dec_session_key) != 0) {
        // Falha na descriptografia! Os dados foram adulterados
    }

    // 4. Liberar com segurança a chave de sessão após o uso
    hsc_secure_free(dec_session_key);
    ```

## 6. 😶 Análise Detalhada da Arquitetura Técnica

O núcleo deste projeto é o modelo de Criptografia Híbrida, que combina as vantagens da criptografia assimétrica e simétrica para alcançar uma transmissão de dados segura e eficiente.

**Diagrama de Fluxo de Dados e Relação de Chaves:**

```
REMETENTE (ALICE)                                        DESTINATÁRIO (BOB)
========================================================================
[Dados Originais] -> Gera [Chave de Sessão]
                      |        |
(Criptografia Simétrica) <---'        '-> (Encapsulamento Assimétrico) Usando: Chave Pública de Bob, Chave Privada de Alice
       |                                      |
[Dados Criptografados]                [Chave de Sessão Encapsulada]
       |                                      |
       '----------------. .-------------------'
                        | |
                        v v
                    [Pacote de Transmissão]
                         |
     ==================> | Rede/Transferência de Arquivos =================>
                         |
                    [Pacote de Transmissão]
                        | |
             .----------' '-------------.
             |                          |
[Chave de Sessão Encapsulada]      [Dados Criptografados]
             |                          |
             v                          |
(Desencapsulamento Assimétrico) Usando: Chave Privada de Bob, Chave Pública de Alice |
             |                          |
             v                          |
        [Chave de Sessão Recuperada] <-$----' (Descriptografia Simétrica)
             |
             v
        [Dados Originais]
```

## 7. 😄 Configuração Avançada: Aumentando a Segurança com Variáveis de Ambiente

Para se adaptar a hardware e requisitos de segurança futuros mais robustos sem modificar o código, este projeto suporta o **aumento** da força computacional da função de derivação de chave (Argon2id) através de variáveis de ambiente.

*   **`HSC_ARGON2_OPSLIMIT`**: Define o número de iterações (computacionais) para o Argon2id.
*   **`HSC_ARGON2_MEMLIMIT`**: Define o uso de memória para o Argon2id (em bytes).

**Nota de Segurança Importante:** Esta funcionalidade **só pode ser usada para aumentar os parâmetros de segurança**. Se os valores definidos nas variáveis de ambiente forem inferiores à linha de base de segurança mínima incorporada no projeto, o programa ignorará automaticamente esses valores inseguros e forçará o uso dos mínimos incorporados.

** Novo Exemplo de Uso:**

```bash
# Exemplo: Aumentar o limite de operações para 10 e o limite de memória para 512MB.
# Nota: HSC_ARGON2_MEMLIMIT precisa ser em bytes.
# 512 * 1024 * 1024 = 536870912 bytes.
export HSC_ARGON2_OPSLIMIT=10
export HSC_ARGON2_MEMLIMIT=536870912

# Executar o programa em um shell onde as variáveis de ambiente estão definidas.
# Ele usará automaticamente esses parâmetros mais fortes.
./bin/hsc_cli gen-keypair my_strong_key
```

## 8. 😀 Referência Principal da API (`include/hsc_kernel.h`)

### Inicialização e Limpeza
| Função | Descrição |
| :--- | :--- |
| `int hsc_init()` | **(Deve ser chamada primeiro)** Inicializa toda a biblioteca. |
| `void hsc_cleanup()` | Chamada antes de o programa sair para liberar recursos globais. |

### Gerenciamento de Chaves
| Função | Descrição |
| :--- | :--- |
| `hsc_master_key_pair* hsc_generate_master_key_pair()` | Gera um novo par de chaves mestras. |
| `hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(...)` | Carrega uma chave privada de um arquivo. |
| `int hsc_save_master_key_pair(...)` | Salva um par de chaves em um arquivo. |
| `void hsc_free_master_key_pair(hsc_master_key_pair** kp)` | Libera com segurança um par de chaves mestras. |

### PKI e Certificados
| Função | Descrição |
| :--- | :--- |
| `int hsc_generate_csr(...)` | Gera uma Solicitação de Assinatura de Certificado (CSR) no formato PEM. |
| `int hsc_verify_user_certificate(...)` | **(Central)** Realiza a verificação completa do certificado (cadeia, validade, assunto, OCSP). |
| `int hsc_extract_public_key_from_cert(...)` | Extrai uma chave pública de um certificado verificado. |

### Encapsulamento de Chave (Assimétrico)
| Função | Descrição |
| :--- | :--- |
| `int hsc_encapsulate_session_key(...)` | Criptografa uma chave de sessão usando a chave pública do destinatário. |
| `int hsc_decapsulate_session_key(...)` | Descriptografa uma chave de sessão usando a chave privada do destinatário. |

### Criptografia de Dados (Simétrica)
| Função | Descrição |
| :--- | :--- |
| `int hsc_aead_encrypt(...)` | Criptografa autenticadamente um **pequeno bloco de dados** usando AEAD. |
| `int hsc_aead_decrypt(...)` | Descriptografa e verifica dados criptografados por `hsc_aead_encrypt`. |

### Criptografia de Fluxo (Simétrica, para arquivos grandes)
| Função | Descrição |
| :--- | :--- |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(...)` | Cria um objeto de estado de fluxo de criptografia. |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(...)` | Cria um objeto de estado de fluxo de descriptografia. |
| `int hsc_crypto_stream_push(...)` | Criptografa um bloco de dados no fluxo. |
| `int hsc_crypto_stream_pull(...)` | Descriptografa um bloco de dados do fluxo. |
| `void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state)` | Libera o objeto de estado do fluxo. |

### Memória Segura
| Função | Descrição |
| :--- | :--- |
| `void* hsc_secure_alloc(size_t size)` | Aloca um bloco de memória protegida e não paginável. |
| `void hsc_secure_free(void* ptr)` | Zera e libera com segurança a memória protegida. |


## 9. 🥳 Contribuição

Congratulamo-nos com contribuições de todas as formas! Se você encontrar um bug, tiver uma sugestão de funcionalidade ou quiser melhorar a documentação, sinta-se à vontade para enviar um Pull Request ou criar uma Issue.

## 10. 🥺 Descrição do Certificado

Este projeto utiliza o sistema de certificados **X.509 v3** para vincular uma chave pública a uma identidade de usuário (como `alice@example.com`), estabelecendo assim a confiança. O processo de verificação do certificado inclui **validação da cadeia de assinaturas**, **verificação da validade**, **verificação da identidade do assunto** e **verificação do status de revogação (OCSP)**, adotando uma política estrita de "fail-closed".

## 11. 🥸 Licença - Modelo de Licenciamento Duplo

Este projeto adota um modelo de **Licenciamento Duplo (Dual-License)**:

### 1. GNU Affero General Public License v3.0 (AGPLv3)
Adequado para projetos de código aberto, pesquisa acadêmica e aprendizado pessoal. Exige que quaisquer trabalhos derivados modificados ou disponibilizados através de uma rede também devam abrir seu código-fonte completo sob a AGPLv3.

### 2. Licença Comercial
Adequado para qualquer aplicativo, produto ou serviço comercial de código fechado. Se você não deseja estar vinculado aos termos de código aberto da AGPLv3, deve obter uma licença comercial.

**Para obter uma licença comercial, entre em contato: `eldric520lol@gmail.com`**