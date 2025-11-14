<div align="center">
  <img src="./src/media/icon-256.png" alt="Oracipher Icon" width="128">
  <h1 style="border-bottom: none;">Oracipher Core</h1>

# Biblioteca de Kernel de Criptografia Híbrida de Alta Segurança

| Build & Test | License | Language | Dependencies |
| :---: | :---: | :---: | :---: |
| ![Build Status](https://img.shields.io/badge/tests-passing-brightgreen) | ![License](https://img.shields.io/badge/license-Dual--Licensed-blue) | ![Language](https://img.shields.io/badge/language-C11-purple) | ![Libsodium](https://img.shields.io/badge/libsodium-v1.0.18+-brightgreen) ![OpenSSL](https://img.shields.io/badge/OpenSSL-v3.0+-0075A8) ![Libcurl](https://img.shields.io/badge/libcurl-v7.68+-E5522D) |

</div>

---

### **Índice**
1.  [Visão do Projeto e Princípios Fundamentais](#1-visão-do-projeto-e-princípios-fundamentais)
2.  [Recursos Principais](#2-recursos-principais)
3.  [Estrutura do Projeto](#3-estrutura-do-projeto)
4.  [Início Rápido](#4-início-rápido)
    *   [4.1 Dependências](#41-dependências)
    *   [4.2 Compilação e Testes](#42-compilação-e-testes)
5.  [Guia de Uso](#5-guia-de-uso)
    *   [5.1 Usando como Ferramenta de Linha de Comando (`hsc_cli` & `test_ca_util`)](#51-usando-como-ferramenta-de-linha-de-comando-hsc_cli--test_ca_util)
    *   [5.2 Usando como uma Biblioteca em seu Projeto](#52-usando-como-uma-biblioteca-em-seu-projeto)
6.  [Análise Aprofundada: Arquitetura Técnica](#6-análise-aprofundada-arquitetura-técnica)
7.  [Configuração Avançada: Aumentando a Segurança com Variáveis de Ambiente](#7-configuração-avançada-aumentando-a-segurança-com-variáveis-de-ambiente)
8.  [Tópico Avançado: Comparação de Modos de Criptografia](#8-tópico-avançado-comparação-de-modos-de-criptografia)
9.  [Referência da API Principal (`include/hsc_kernel.h`)](#9-referência-da-api-principal-includehsc_kernelh)
10. [Contribuição](#10-contribuição)
11. [Notas sobre Certificados](#11-notas-sobre-certificados)
12. [Licença - Modelo de Licenciamento Duplo](#12-licença---modelo-de-licenciamento-duplo)

---

## 1. Visão do Projeto e Princípios Fundamentais

Este projeto é uma biblioteca de kernel de criptografia híbrida avançada, focada em segurança e implementada em C11. Seu objetivo é fornecer um modelo testado em batalha que demonstra como combinar bibliotecas criptográficas líderes da indústria (**libsodium**, **OpenSSL**, **libcurl**) em uma solução de criptografia de ponta a ponta robusta, confiável e fácil de usar.

Nosso design adere aos seguintes princípios fundamentais de segurança:

*   **Escolher Criptografia Moderna e Auditada:** Nunca implementamos nossa própria criptografia. Usamos apenas primitivas criptográficas modernas amplamente reconhecidas pela comunidade e resistentes a ataques de canal lateral.
*   **Defesa em Profundidade:** A segurança não depende de uma única camada. Implementamos proteções em múltiplos níveis, incluindo gerenciamento de memória, design de API e fluxo de protocolo.
*   **Padrões Seguros e Política de "Falha Segura" (Fail-Closed):** O comportamento padrão do sistema deve ser seguro. Diante de um estado incerto (por exemplo, incapacidade de verificar o status de revogação de um certificado), o sistema deve optar por falhar e encerrar a operação (fail-closed) em vez de continuar.
*   **Minimizar a Exposição de Dados Sensíveis:** Controlamos rigorosamente o ciclo de vida, o escopo e o tempo de permanência na memória de dados críticos como chaves privadas, mantendo-os no mínimo absoluto necessário.

## 2. Recursos Principais

*   **Modelo Robusto de Criptografia Híbrida:**
    *   **Criptografia Simétrica:** Fornece criptografia de fluxo AEAD (para grandes blocos de dados) e criptografia AEAD de uso único (para pequenos blocos de dados) baseada em **XChaCha20-Poly1305**.
    *   **Criptografia Assimétrica:** Usa **X25519** (baseado na Curve2519) para um Mecanismo de Encapsulamento de Chave (KEM) para envolver a chave de sessão simétrica, garantindo que apenas o destinatário pretendido possa descriptografá-la.

*   **Pilha de Primitivas Criptográficas Modernas:**
    *   **Derivação de Chave:** Emprega **Argon2id**, o vencedor da Competição de Hashing de Senhas, para resistir eficazmente a tentativas de quebra por GPU e ASIC.
    *   **Assinaturas Digitais:** Utiliza **Ed25519** para capacidades de assinatura digital de alta velocidade e alta segurança.
    *   **Chaves Unificadas:** Utiliza de forma inteligente a característica de que chaves Ed25519 podem ser convertidas com segurança em chaves X25519, permitindo que um único par de chaves mestras atenda às necessidades de assinatura e criptografia.

*   **Suporte Abrangente à Infraestrutura de Chave Pública (PKI):**
    *   **Ciclo de Vida do Certificado:** Suporta a geração de Solicitações de Assinatura de Certificado (CSRs) compatíveis com X.509 v3.
    *   **Validação Estrita de Certificados:** Fornece um processo padronizado de validação de certificados, incluindo cadeia de confiança, período de validade e correspondência de sujeito.
    *   **Verificação Obrigatória de Revogação (OCSP):** Possui verificações rigorosas e integradas do Protocolo de Status de Certificado Online (OCSP) com uma política de "falha segura". Se o bom estado do certificado não puder ser confirmado, a operação é imediatamente abortada.

*   **Segurança de Memória Sólida como uma Rocha:**
    *   Expõe as funções de memória segura do `libsodium` através da API pública, permitindo que os clientes manipulem dados sensíveis (como chaves de sessão) com segurança.
    *   **[Documentado com Segurança]** Todas as chaves privadas internas **e outros segredos críticos (por exemplo, sementes de chave, valores de hash intermediários)** são armazenados em memória bloqueada, **impedindo que sejam trocados para o disco pelo SO**, e são zerados com segurança antes de serem liberados. As fronteiras com bibliotecas de terceiros (como OpenSSL) são cuidadosamente gerenciadas. Quando dados sensíveis devem cruzar para regiões de memória padrão (por exemplo, ao passar uma semente para o OpenSSL em `generate_csr`), esta biblioteca emprega técnicas de defesa em profundidade (como limpar imediatamente os buffers de memória após o uso) para mitigar os riscos inerentes, representando uma abordagem de melhores práticas ao interagir com bibliotecas que não são conscientes da segurança de memória.

*   **Práticas de Engenharia de Alta Qualidade:**
    *   **Interface de API Limpa:** Fornece um único arquivo de cabeçalho público, `hsc_kernel.h`, que encapsula todos os detalhes de implementação interna usando ponteiros opacos, alcançando alta coesão e baixo acoplamento.
    *   **Conjunto de Testes Abrangente:** Inclui um conjunto de testes de unidade e integração que cobrem a criptografia principal, PKI e funções de API de alto nível para garantir a correção e confiabilidade do código.
    *   **Sistema de Log Desacoplado:** Implementa um mecanismo de log baseado em callback, dando à aplicação cliente controle total sobre como e onde as mensagens de log são exibidas, tornando a biblioteca adequada para qualquer ambiente.
    *   **Documentação e Exemplos Exaustivos:** Fornece um `README.md` detalhado, juntamente com um programa de demonstração pronto para rodar e uma poderosa ferramenta de linha de comando.

## 3. Estrutura do Projeto

O projeto utiliza uma estrutura de diretórios limpa e em camadas para alcançar a separação de responsabilidades.

```.
├── include/
│   └── hsc_kernel.h      # [Principal] O único cabeçalho público da API
├── src/                  # Código Fonte
│   ├── common/           # Módulos internos comuns (memória segura, log)
│   ├── core_crypto/      # Módulos internos de criptografia (wrappers do libsodium)
│   ├── pki/              # Módulos internos de PKI (wrappers do OpenSSL, libcurl)
│   ├── hsc_kernel.c      # [Principal] Implementação da API pública
│   ├── main.c            # Exemplo de uso da API: Programa de demonstração de ponta a ponta
│   └── cli.c             # Exemplo de uso da API: Ferramenta de linha de comando poderosa
├── tests/                # Testes de unidade e utilitários de teste
│   ├── test_*.c          # Testes de unidade para vários módulos
│   ├── test_api_integration.c # [Novo] Testes de ponta a ponta para APIs de alto nível
│   ├── test_helpers.h/.c # Funções auxiliares de teste (geração de CA, assinatura)
│   └── test_ca_util.c    # Código fonte do utilitário de CA de teste autônomo
├── Makefile              # Script de compilação e gerenciamento de tarefas
└── README.md             # A documentação deste projeto
```

## 4. Início Rápido

### 4.1 Dependências

*   **Ferramentas de Compilação:** `make`
*   **Compilador C:** `gcc` ou `clang` (com suporte a C11 e `-Werror`)
*   **libsodium:** (`libsodium-dev`)
*   **OpenSSL:** **v3.0** ou mais recente é recomendado (`libssl-dev`)
*   **libcurl:** (`libcurl4-openssl-dev`)

**Instalação nos Principais Sistemas:**

*   **Debian/Ubuntu:**
    ```bash
    sudo apt-get update
    sudo apt-get install build-essential libsodium-dev libssl-dev libcurl4-openssl-dev
    ```
*   **Fedora/RHEL/CentOS:**
    ```bash
    sudo dnf install gcc make libsodium-devel openssl-devel libcurl-devel
    ```
*   **macOS (usando Homebrew):**
    ```bash
    brew install libsodium openssl@3 curl
    ```

### 4.2 Compilação e Testes

O projeto foi projetado para ser altamente portátil e evita caminhos codificados específicos da plataforma, garantindo que ele compile e execute corretamente em todos os sistemas suportados.

1.  **Compilar Todos os Alvos (biblioteca, demo, CLI, testes):**
    ```bash
    make all
    ```

2.  **Executar o Conjunto Completo de Testes (Passo Crítico):**
    ```bash
    make run-tests
    ```
    > **Nota Importante sobre o Comportamento Esperado do Teste OCSP**
    >
    > Um caso de teste em `test_pki_verification` valida intencionalmente um certificado que aponta para um servidor OCSP local inexistente (`http://127.0.0.1:8888`). A requisição de rede falhará, e nesse ponto a função `hsc_verify_user_certificate` **deve** retornar `-12` (o código de erro para `HSC_ERROR_CERT_REVOKED_OR_OCSP_FAILED`). O programa de teste verifica esse valor de retorno específico.
    >
    > Esta "falha" é o **comportamento esperado e correto**, pois demonstra perfeitamente que nossa política de segurança de "falha segura" está corretamente implementada: **se o status de revogação de um certificado não puder ser confirmado por qualquer motivo, ele é tratado como inválido.**

3.  **Executar o Programa de Demonstração:**
    ```bash
    ./bin/hsc_demo
    ```

4.  **Explorar a Ferramenta de Linha de Comando:**
    ```bash
    ./bin/hsc_cli
    ```

5.  **Limpar Arquivos de Compilação:**
    ```bash
    make clean
    ```

## 5. Guia de Uso

### 5.1 Usando como Ferramenta de Linha de Comando (`hsc_cli` & `test_ca_util`)

Esta seção fornece um fluxo de trabalho completo e autocontido, demonstrando como dois usuários, Alice e Bob, podem realizar uma troca segura de arquivos usando as ferramentas de linha de comando fornecidas.

**Funções das Ferramentas:**
*   `./bin/test_ca_util`: Um utilitário auxiliar que simula uma Autoridade Certificadora (CA), responsável por gerar um certificado raiz e assinar certificados de usuário.
*   `./bin/hsc_cli`: A ferramenta cliente principal para geração de chaves, criação de CSR, validação de certificados e criptografia/descriptografia de arquivos.

**Exemplo de Fluxo de Trabalho Completo: Alice Criptografa um Arquivo e o Envia com Segurança para Bob**

1.  **(Configuração) Criar uma Autoridade Certificadora de Teste (CA):**
    *Usamos o `test_ca_util` para gerar uma chave CA raiz e um certificado autoassinado.*
    ```bash
    ./bin/test_ca_util gen-ca ca.key ca.pem
    ```

2.  **(Alice & Bob) Gerar seus Pares de Chaves Mestras:**
    ```bash
    ./bin/hsc_cli gen-keypair alice
    ./bin/hsc_cli gen-keypair bob
    ```
    *Isso cria `alice.key`, `alice.pub`, `bob.key` e `bob.pub`.*

3.  **(Alice & Bob) Gerar Solicitações de Assinatura de Certificado (CSRs):**
    ```bash
    ./bin/hsc_cli gen-csr alice.key "alice@example.com"
    ./bin/hsc_cli gen-csr bob.key "bob@example.com"
    ```
    *Isso cria `alice.csr` e `bob.csr`.*

4.  **(CA) Assinar os CSRs para Emitir Certificados:**
    *A CA usa sua chave privada (`ca.key`) e certificado (`ca.pem`) para assinar os CSRs.*
    ```bash
    ./bin/test_ca_util sign alice.csr ca.key ca.pem alice.pem
    ./bin/test_ca_util sign bob.csr ca.key ca.pem bob.pem
    ```
    *Alice e Bob agora têm seus certificados oficiais, `alice.pem` e `bob.pem`.*

5.  **(Alice) Verifica o Certificado de Bob Antes de Enviar:**
    *Alice usa o certificado CA confiável (`ca.pem`) para verificar a identidade de Bob. Este é um passo crítico antes de confiar em seu certificado.*
    ```bash
    ./bin/hsc_cli verify-cert bob.pem --ca ca.pem --user "bob@example.com"
    ```

6.  **(Alice) Criptografa um Arquivo para Bob:**
    *Alice agora tem várias opções:*

    **Opção A: Baseado em Certificado com Validação (Padrão Seguro & Recomendado)**
    > Esta é a maneira padrão e segura de operar. A ferramenta **exige** que Alice forneça o certificado da CA e o nome de usuário esperado para realizar uma validação completa e estrita do certificado de Bob antes de criptografar.
    ```bash
    echo "This is top secret information." > secret.txt
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key --ca ca.pem --user "bob@example.com"
    ```

    **Opção B: Baseado em Certificado sem Validação (Perigoso - Apenas para Usuários Avançados)**
    > Se Alice tem certeza absoluta da autenticidade do certificado e deseja pular a validação, ela deve usar explicitamente a flag `--no-verify`. **Isso não é recomendado.**
    ```bash
    # Use com extrema cautela!
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key --no-verify
    ```

    **Opção C: Modo de Chave Direta (Avançado - Para Chaves Pré-confiadas)**
    *Se Alice já obteve a chave pública de Bob (`bob.pub`) através de um canal seguro e confiável, ela pode criptografar diretamente para ela, ignorando toda a lógica de certificados.*
    ```bash
    ./bin/hsc_cli encrypt secret.txt --recipient-pk-file bob.pub --from alice.key
    ```
    *Todas as opções criam `secret.txt.hsc`. Alice agora pode enviar `secret.txt.hsc` e seu certificado `alice.pem` para Bob.*

7.  **(Bob) Descriptografa o Arquivo ao Receber:**
    *Bob usa sua chave privada (`bob.key`) para descriptografar o arquivo. Dependendo de como Alice o criptografou, ele precisará do certificado dela (`alice.pem`) ou de sua chave pública bruta (`alice.pub`).*

    **Se Alice Usou a Opção A ou B (Certificado):**
    ```bash
    ./bin/hsc_cli decrypt secret.txt.hsc --to bob.key --from alice.pem
    ```

    **Se Alice Usou a Opção C (Chave Direta):**
    ```bash
    ./bin/hsc_cli decrypt secret.txt.hsc --to bob.key --sender-pk-file alice.pub
    ```
    *Ambos os comandos produzirão `secret.txt.decrypted`.*
    ```bash
    cat secret.txt.decrypted
    ```

### 5.2 Usando como uma Biblioteca em seu Projeto

`src/main.c` serve como um excelente exemplo de integração. Um fluxo de chamada de API típico é o seguinte:

1.  **Inicialização Global e Configuração de Log:** Chame `hsc_init()` na inicialização e registre um callback de log.
    ```c
    #include "hsc_kernel.h"
    #include <stdio.h>

    // Defina uma função de log simples para sua aplicação
    void my_app_logger(int level, const char* message) {
        // Exemplo: Imprime erros para stderr, informações para stdout
        if (level >= 2) { // 2 = ERROR
            fprintf(stderr, "[HSC_LIB_ERROR] %s\n", message);
        } else {
            printf("[HSC_LIB_INFO] %s\n", message);
        }
    }

    int main() {
        if (hsc_init() != HSC_OK) {
            // Lidar com erro fatal
        }
        // Registre sua função de log com a biblioteca
        hsc_set_log_callback(my_app_logger);

        // ... Seu código ...
        hsc_cleanup();
        return 0;
    }
    ```

2.  **Remetente (Alice) Criptografa Dados:**
    ```c
    // 1. Gere uma chave de sessão de uso único
    unsigned char session_key[HSC_SESSION_KEY_BYTES];
    hsc_random_bytes(session_key, sizeof(session_key));

    // 2. Criptografe dados com a chave de sessão usando AEAD (para dados pequenos)
    const char* message = "Secret message";
    // ... (a lógica de criptografia é a mesma do exemplo) ...

    // 3. Verifique o certificado do destinatário (Bob)
    if (hsc_verify_user_certificate(bob_cert_pem, ca_pem, "bob@example.com") != HSC_OK) {
        // Certificado é inválido, aborte! A biblioteca registrará detalhes via seu callback.
    }

    // 4. Extraia a chave pública de Bob de seu certificado
    unsigned char bob_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    if (hsc_extract_public_key_from_cert(bob_cert_pem, bob_pk) != HSC_OK) {
        // Lidar com erro de extração
    }

    // 5. Encapsule a chave de sessão
    // ... (a lógica de encapsulamento é a mesma do exemplo) ...
    ```

3.  **Receptor (Bob) Descriptografa Dados:**
    *A lógica de descriptografia permanece a mesma, mas quaisquer erros internos durante a desencapsulação ou descriptografia AEAD agora serão reportados através do seu callback `my_app_logger` registrado, em vez de poluir `stderr` diretamente.*

## 6. Análise Aprofundada: Arquitetura Técnica

O núcleo deste projeto é um modelo de criptografia híbrida que combina as vantagens da criptografia assimétrica e simétrica para alcançar uma transferência de dados segura e eficiente.

**Fluxo de Dados e Diagrama de Relacionamento de Chaves:**

```
REMETENTE (ALICE)                                        RECEPTOR (BOB)
========================================================================
           [ Texto Simples ] --> Gerar [ Chave de Sessão ]
                           |           |
(Criptografia Simétrica) <-'           '-> (Encapsulamento Assimétrico) usando: Chave Pública de Bob, Chave Privada de Alice
       |                                             |
[ Dados Criptografados ]               [ Chave de Sessão Encapsulada ]
       |                                             |
       '---------------------.   .-------------------'
                             |   |
                             v   v
                         [ Pacote de Dados ]
                             |
    ==================>  Pela Rede/Arquivo  =================>
                             |
                         [ Pacote de Dados ]
                             |   |
             .---------------'   '-----------------.
             |                                     |
[ Chave de Sessão Encapsulada ]         [ Dados Criptografados ]
             |                                     |
             v                                     |
(Desencapsulamento Assimétrico) usando: Chave Privada de Bob, Chave Pública de Alice
             |                                     |
             v                                     |
        [ Chave de Sessão Recuperada ] <-$-----' (Descriptografia Simétrica)
             |
             v
        [ Texto Simples ]
```

## 7. Configuração Avançada: Aumentando a Segurança com Variáveis de Ambiente

Para se adaptar a futuras necessidades de hardware e segurança sem modificação de código, este projeto suporta o **aumento** do custo computacional da função de derivação de chave (Argon2id) através de variáveis de ambiente.

*   **`HSC_ARGON2_OPSLIMIT`**: Define o número de operações (rodadas computacionais) para o Argon2id.
*   **`HSC_ARGON2_MEMLIMIT`**: Define o uso de memória em bytes para o Argon2id.

**Nota de Segurança Importante:** Este recurso **só pode ser usado para fortalecer os parâmetros de segurança**. Se os valores definidos nas variáveis de ambiente forem inferiores às linhas de base de segurança mínimas incorporadas ao projeto, o programa ignorará automaticamente os valores inseguros e aplicará os mínimos incorporados.

**Exemplo de Uso:**

```bash
# Exemplo: Aumentar o limite de operações para 10 e o limite de memória para 512MB.
# Nota: HSC_ARGON2_MEMLIMIT requer o valor em bytes.
# 512 * 1024 * 1024 = 536870912 bytes.
export HSC_ARGON2_OPSLIMIT=10
export HSC_ARGON2_MEMLIMIT=536870912

# Qualquer programa executado em um shell com essas variáveis definidas usará automaticamente esses parâmetros mais fortes.
./bin/hsc_cli gen-keypair my_strong_key
```

## 8. Tópico Avançado: Comparação de Modos de Criptografia

O Oracipher Core fornece dois fluxos de trabalho de criptografia híbrida distintos, cada um com diferentes garantias de segurança. Escolher o correto é crucial.

### Fluxo de Trabalho Baseado em Certificado (Padrão & Recomendado)

*   **Como Funciona:** Usa certificados X.509 para vincular a identidade de um usuário (por exemplo, `bob@example.com`) à sua chave pública.
*   **Garantias de Segurança:**
    *   **Autenticação:** Verifica criptograficamente que a chave pública realmente pertence ao destinatário pretendido.
    *   **Integridade:** Garante que o certificado não foi adulterado.
    *   **Verificação de Revogação:** Verifica ativamente via OCSP se o certificado foi revogado pela autoridade emissora.
*   **Quando Usar:** Em qualquer cenário onde o remetente e o receptor não têm um canal preexistente e altamente seguro para trocar chaves públicas. Este é o padrão para a maioria das comunicações baseadas na internet.

### Fluxo de Trabalho de Chave Direta (Bruta) (Avançado)

*   **Como Funciona:** Ignora toda a lógica de PKI e certificados, criptografando diretamente para um arquivo de chave pública bruta.
*   **Garantias de Segurança:**
    *   Fornece o mesmo nível de **confidencialidade** e **integridade** para os dados criptografados em si que o modo de certificado.
*   **Compromissos de Segurança:**
    *   **Sem Autenticação:** Este modo **não** verifica a identidade do proprietário da chave. O usuário é o único responsável por garantir a autenticidade da chave pública que está usando. Usar uma chave pública incorreta ou maliciosa resultará na criptografia dos dados para a parte errada.
*   **Quando Usar:** Apenas em sistemas fechados ou protocolos específicos onde as chaves públicas foram trocadas e verificadas através de um mecanismo fora de banda independente e confiável (por exemplo, chaves gravadas no firmware de um dispositivo seguro ou verificadas pessoalmente).

## 9. Referência da API Principal (`include/hsc_kernel.h`)

### Inicialização e Limpeza
| Função | Descrição |
| :--- | :--- |
| `int hsc_init()` | **(Deve ser chamada primeiro)** Inicializa toda a biblioteca. |
| `void hsc_cleanup()` | Chame antes da saída do programa para liberar recursos globais. |

### Gerenciamento de Chaves
| Função | Descrição |
| :--- | :--- |
| `hsc_master_key_pair* hsc_generate_master_key_pair()` | Gera um novo par de chaves mestras. |
| `hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(...)` | Carrega uma chave privada de um arquivo. |
| `int hsc_save_master_key_pair(...)` | Salva um par de chaves em arquivos. |
| `void hsc_free_master_key_pair(hsc_master_key_pair** kp)` | Libera com segurança um par de chaves mestras. |
| `int hsc_get_master_public_key(const hsc_master_key_pair* kp, ...)` | **[Novo]** Extrai a chave pública bruta de um handle de par de chaves. |

### PKI e Certificados
| Função | Descrição |
| :--- | :--- |
| `int hsc_generate_csr(...)` | Gera uma Solicitação de Assinatura de Certificado (CSR) formatada em PEM. |
| `int hsc_verify_user_certificate(...)` | **(Principal)** Realiza a validação completa do certificado (cadeia, validade, sujeito, OCSP). |
| `int hsc_extract_public_key_from_cert(...)` | Extrai uma chave pública de um certificado verificado. |

### Encapsulamento de Chave (Assimétrico)
| Função | Descrição |
| :--- | :--- |
| `int hsc_encapsulate_session_key(...)` | Criptografa uma chave de sessão usando a chave pública do destinatário. |
| `int hsc_decapsulate_session_key(...)` | Descriptografa uma chave de sessão usando a chave privada do destinatário. |

### Criptografia de Fluxo (Simétrica, para arquivos grandes)
| Função | Descrição |
| :--- | :--- |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(...)` | Cria um objeto de estado de fluxo de criptografia. |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(...)` | Cria um objeto de estado de fluxo de descriptografia. |
| `int hsc_crypto_stream_push(...)` | Criptografa um pedaço de dados em um fluxo. |
| `int hsc_crypto_stream_pull(...)` | Descriptografa um pedaço de dados em um fluxo. |
| `void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state)` | Libera um objeto de estado de fluxo. |
| `int hsc_hybrid_encrypt_stream_raw(...)` | Realiza criptografia híbrida completa em um arquivo usando uma chave pública bruta. |
| `int hsc_hybrid_decrypt_stream_raw(...)` | Realiza descriptografia híbrida completa em um arquivo usando uma chave pública bruta. |

### Criptografia de Dados (Simétrica, para dados pequenos)
| Função | Descrição |
| :--- | :--- |
| `int hsc_aead_encrypt(...)` | Realiza criptografia autenticada em um **pequeno pedaço de dados** usando AEAD. |
| `int hsc_aead_decrypt(...)` | Descriptografa e verifica dados criptografados por `hsc_aead_encrypt`. |

### Memória Segura
| Função | Descrição |
| :--- | :--- |
| `void* hsc_secure_alloc(size_t size)` | Aloca um bloco de memória protegido e não trocável. |
| `void hsc_secure_free(void* ptr)` | Zera e libera com segurança um bloco de memória protegido. |

### Log
| Função | Descrição |
| :--- | :--- |
| `void hsc_set_log_callback(hsc_log_callback callback)` | **[Novo]** Registra uma função de callback para lidar com todos os logs internos da biblioteca. |

## 10. Contribuição

Acolhemos todas as formas de contribuição! Se você encontrar um bug, tiver uma sugestão de recurso ou quiser melhorar a documentação, sinta-se à vontade para enviar um Pull Request ou criar uma Issue.

## 11. Notas sobre Certificados

Este projeto usa um sistema de certificados **X.509 v3** para vincular chaves públicas a identidades de usuário (por exemplo, `alice@example.com`), estabelecendo assim a confiança. O processo de validação de certificados inclui **validação da cadeia de assinaturas**, **verificação do período de validade**, **verificação da identidade do sujeito** e **verificação do status de revogação (OCSP)**, tudo sob uma estrita política de "falha segura".

## 12. Licença - Modelo de Licenciamento Duplo

Este projeto é distribuído sob um modelo de **licenciamento duplo**:

### 1. GNU Affero General Public License v3.0 (AGPLv3)
Esta licença é adequada para projetos de código aberto, pesquisa acadêmica e estudo pessoal. Ela exige que quaisquer trabalhos derivados, sejam eles modificados ou oferecidos como serviço em uma rede, também tenham seu código-fonte completo disponibilizado sob a AGPLv3.

### 2. Licença Comercial
Uma licença comercial deve ser obtida para quaisquer aplicações, produtos ou serviços comerciais de código fechado. Se você não deseja estar vinculado aos termos de código aberto da AGPLv3, deve adquirir uma licença comercial.

**Para obter uma licença comercial, entre em contato com: `eldric520lol@gmail.com`**