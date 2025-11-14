<div align="center">
  <img src="./src/media/icon-256.png" alt="Oracipher Icon" width="128">
  <h1 style="border-bottom: none;">Oracipher Core</h1>

# Biblioteca de Kernel de Cifrado Híbrido de Alta Seguridad

| Build & Test | License | Language | Dependencies |
| :---: | :---: | :---: | :---: |
| ![Build Status](https://img.shields.io/badge/tests-passing-brightgreen) | ![License](https://img.shields.io/badge/license-Dual--Licensed-blue) | ![Language](https://img.shields.io/badge/language-C11-purple) | ![Libsodium](https://img.shields.io/badge/libsodium-v1.0.18+-brightgreen) ![OpenSSL](https://img.shields.io/badge/OpenSSL-v3.0+-0075A8) ![Libcurl](https://img.shields.io/badge/libcurl-v7.68+-E5522D) |

</div>

---

### **Tabla de Contenidos**
1.  [Visión del Proyecto y Principios Fundamentales](#1-visión-del-proyecto-y-principios-fundamentales)
2.  [Características Principales](#2-características-principales)
3.  [Estructura del Proyecto](#3-estructura-del-proyecto)
4.  [Inicio Rápido](#4-inicio-rápido)
    *   [4.1 Dependencias](#41-dependencias)
    *   [4.2 Compilación y Pruebas](#42-compilación-y-pruebas)
5.  [Guía de Uso](#5-guía-de-uso)
    *   [5.1 Uso como Herramienta de Línea de Comandos (`hsc_cli` & `test_ca_util`)](#51-uso-como-herramienta-de-línea-de-comandos-hsc_cli--test_ca_util)
    *   [5.2 Uso como Biblioteca en su Proyecto](#52-uso-como-biblioteca-en-su-proyecto)
6.  [Análisis Profundo: Arquitectura Técnica](#6-análisis-profundo-arquitectura-técnica)
7.  [Configuración Avanzada: Mejorando la Seguridad con Variables de Entorno](#7-configuración-avanzada-mejorando-la-seguridad-con-variables-de-entorno)
8.  [Tema Avanzado: Comparación de Modos de Cifrado](#8-tema-avanzado-comparación-de-modos-de-cifrado)
9.  [Referencia de la API Principal (`include/hsc_kernel.h`)](#9-referencia-de-la-api-principal-includehsc_kernelh)
10. [Contribuciones](#10-contribuciones)
11. [Notas sobre Certificados](#11-notas-sobre-certificados)
12. [Licencia - Modelo de Licencia Dual](#12-licencia---modelo-de-licencia-dual)

---

## 1. Visión del Proyecto y Principios Fundamentales

Este proyecto es una biblioteca de kernel de cifrado híbrido avanzada, centrada en la seguridad e implementada en C11. Su objetivo es proporcionar un plano probado en batalla que demuestre cómo combinar bibliotecas criptográficas líderes en la industria (**libsodium**, **OpenSSL**, **libcurl**) en una solución de cifrado de extremo a extremo robusta, fiable y fácil de usar.

Nuestro diseño se adhiere a los siguientes principios fundamentales de seguridad:

*   **Elegir Criptografía Moderna y Verificada:** Nunca creamos nuestra propia criptografía. Solo utilizamos primitivas criptográficas modernas que son ampliamente reconocidas por la comunidad y resistentes a ataques de canal lateral.
*   **Defensa en Profundidad:** La seguridad no depende de una sola capa. Implementamos protecciones en múltiples niveles, incluyendo la gestión de memoria, el diseño de la API y el flujo del protocolo.
*   **Valores Predeterminados Seguros y Política de "Fallo Cerrado" (Fail-Closed):** El comportamiento predeterminado del sistema debe ser seguro. Ante un estado incierto (p. ej., no se puede verificar el estado de revocación de un certificado), el sistema debe optar por fallar y terminar la operación (fallo cerrado) en lugar de continuar.
*   **Minimizar la Exposición de Datos Sensibles:** Controlamos estrictamente el ciclo de vida, el alcance y la residencia en memoria de datos críticos como las claves privadas, manteniéndolos al mínimo absoluto necesario.

## 2. Características Principales

*   **Modelo Robusto de Cifrado Híbrido:**
    *   **Cifrado Simétrico:** Proporciona cifrado de flujo AEAD (para grandes bloques de datos) y cifrado AEAD de un solo uso (para pequeños bloques de datos) basado en **XChaCha20-Poly1305**.
    *   **Cifrado Asimétrico:** Utiliza **X25519** (basado en Curve2519) para un Mecanismo de Encapsulación de Claves (KEM) para envolver la clave de sesión simétrica, asegurando que solo el destinatario previsto pueda descifrarla.

*   **Pila de Primitivas Criptográficas Modernas:**
    *   **Derivación de Claves:** Emplea **Argon2id**, el ganador de la Competición de Hashing de Contraseñas, para resistir eficazmente los intentos de craqueo por GPU y ASIC.
    *   **Firmas Digitales:** Aprovecha **Ed25519** para capacidades de firma digital de alta velocidad y alta seguridad.
    *   **Claves Unificadas:** Utiliza inteligentemente la característica de que las claves Ed25519 se pueden convertir de forma segura en claves X25519, permitiendo que un único par de claves maestras satisfaga tanto las necesidades de firma como de cifrado.

*   **Soporte Integral de Infraestructura de Clave Pública (PKI):**
    *   **Ciclo de Vida del Certificado:** Soporta la generación de Solicitudes de Firma de Certificado (CSRs) compatibles con X.509 v3.
    *   **Validación Estricta de Certificados:** Proporciona un proceso de validación de certificados estandarizado, que incluye cadena de confianza, período de validez y coincidencia del sujeto.
    *   **Comprobación Obligatoria de Revocación (OCSP):** Incluye comprobaciones estrictas e integradas del Protocolo de Estado de Certificados en Línea (OCSP) con una política de "fallo cerrado". Si no se puede confirmar el buen estado del certificado, la operación se aborta inmediatamente.

*   **Seguridad de Memoria Sólida como una Roca:**
    *   Expone las funciones de memoria segura de `libsodium` a través de la API pública, permitiendo a los clientes manejar datos sensibles (como claves de sesión) de forma segura.
    *   **[Documentado de Forma Segura]** Todas las claves privadas internas **y otros secretos críticos (p. ej., semillas de clave, valores de hash intermedios)** se almacenan en memoria bloqueada, **evitando que el sistema operativo los intercambie al disco**, y se borran de forma segura antes de ser liberados. Los límites con bibliotecas de terceros (como OpenSSL) se gestionan cuidadosamente. Cuando los datos sensibles deben cruzar a regiones de memoria estándar (p. ej., al pasar una semilla a OpenSSL en `generate_csr`), esta biblioteca emplea técnicas de defensa en profundidad (como limpiar inmediatamente los búferes de memoria después de su uso) para mitigar los riesgos inherentes, lo que representa un enfoque de mejores prácticas al interactuar con bibliotecas que no son conscientes de la memoria segura.

*   **Prácticas de Ingeniería de Alta Calidad:**
    *   **Límite de API Claro:** Proporciona un único archivo de cabecera público, `hsc_kernel.h`, que encapsula todos los detalles de implementación interna mediante punteros opacos, logrando una alta cohesión y un bajo acoplamiento.
    *   **Suite de Pruebas Completa:** Incluye un conjunto de pruebas unitarias y de integración que cubren la criptografía principal, PKI y funciones de API de alto nivel para garantizar la corrección y fiabilidad del código.
    *   **Sistema de Registro Desacoplado:** Implementa un mecanismo de registro basado en callbacks, dando a la aplicación cliente un control total sobre cómo y dónde se muestran los mensajes de registro, haciendo que la biblioteca sea adecuada para cualquier entorno.
    *   **Documentación y Ejemplos Exhaustivos:** Proporciona un `README.md` detallado, junto con un programa de demostración listo para ejecutar y una potente herramienta de línea de comandos.

## 3. Estructura del Proyecto

El proyecto utiliza una estructura de directorios limpia y por capas para lograr la separación de responsabilidades.

```.
├── include/
│   └── hsc_kernel.h      # [Principal] El único archivo de cabecera público de la API
├── src/                  # Código Fuente
│   ├── common/           # Módulos internos comunes (memoria segura, registro)
│   ├── core_crypto/      # Módulos internos de criptografía (wrappers de libsodium)
│   ├── pki/              # Módulos internos de PKI (wrappers de OpenSSL, libcurl)
│   ├── hsc_kernel.c      # [Principal] Implementación de la API pública
│   ├── main.c            # Ejemplo de uso de la API: Programa de demostración de extremo a extremo
│   └── cli.c             # Ejemplo de uso de la API: Potente herramienta de línea de comandos
├── tests/                # Pruebas unitarias y utilidades de prueba
│   ├── test_*.c          # Pruebas unitarias para varios módulos
│   ├── test_api_integration.c # [Nuevo] Pruebas de extremo a extremo para APIs de alto nivel
│   ├── test_helpers.h/.c # Funciones de ayuda para pruebas (generación de CA, firma)
│   └── test_ca_util.c    # Código fuente de la utilidad de CA de prueba independiente
├── Makefile              # Script de compilación y gestión de tareas
└── README.md             # La documentación de este proyecto
```

## 4. Inicio Rápido

### 4.1 Dependencias

*   **Herramientas de Compilación:** `make`
*   **Compilador C:** `gcc` o `clang` (con soporte para C11 y `-Werror`)
*   **libsodium:** (`libsodium-dev`)
*   **OpenSSL:** Se recomienda **v3.0** o superior (`libssl-dev`)
*   **libcurl:** (`libcurl4-openssl-dev`)

**Instalación en Sistemas Principales:**

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

### 4.2 Compilación y Pruebas

El proyecto está diseñado para ser altamente portable y evita rutas codificadas específicas de la plataforma, asegurando que se compile y ejecute correctamente en todos los sistemas compatibles.

1.  **Compilar todos los objetivos (biblioteca, demo, CLI, pruebas):**
    ```bash
    make all
    ```

2.  **Ejecutar la suite de pruebas completa (Paso Crítico):**
    ```bash
    make run-tests
    ```
    > **Nota Importante sobre el Comportamiento Esperado de la Prueba OCSP**
    >
    > Un caso de prueba en `test_pki_verification` valida intencionadamente un certificado que apunta a un servidor OCSP local inexistente (`http://127.0.0.1:8888`). La solicitud de red fallará, momento en el cual la función `hsc_verify_user_certificate` **debe** devolver `-12` (el código de error para `HSC_ERROR_CERT_REVOKED_OR_OCSP_FAILED`). El programa de prueba afirma este valor de retorno específico.
    >
    > Este "fallo" es el **comportamiento esperado y correcto**, ya que demuestra perfectamente que nuestra política de seguridad de "fallo cerrado" está implementada correctamente: **si el estado de revocación de un certificado no se puede confirmar por cualquier motivo, se trata como inválido.**

3.  **Ejecutar el programa de demostración:**
    ```bash
    ./bin/hsc_demo
    ```

4.  **Explorar la herramienta de línea de comandos:**
    ```bash
    ./bin/hsc_cli
    ```

5.  **Limpiar los archivos de compilación:**
    ```bash
    make clean
    ```

## 5. Guía de Uso

### 5.1 Uso como Herramienta de Línea de Comandos (`hsc_cli` & `test_ca_util`)

Esta sección proporciona un flujo de trabajo completo y autónomo que demuestra cómo dos usuarios, Alice y Bob, pueden realizar un intercambio seguro de archivos utilizando las herramientas de línea de comandos proporcionadas.

**Roles de las Herramientas:**
*   `./bin/test_ca_util`: Una utilidad de ayuda que simula una Autoridad de Certificación (CA), responsable de generar un certificado raíz y firmar certificados de usuario.
*   `./bin/hsc_cli`: La herramienta cliente principal para la generación de claves, creación de CSR, validación de certificados y cifrado/descifrado de archivos.

**Ejemplo de Flujo de Trabajo Completo: Alice Cifra un Archivo y lo Envía de Forma Segura a Bob**

1.  **(Configuración) Crear una Autoridad de Certificación de Prueba (CA):**
    *Usamos `test_ca_util` para generar una clave de CA raíz y un certificado autofirmado.*
    ```bash
    ./bin/test_ca_util gen-ca ca.key ca.pem
    ```

2.  **(Alice y Bob) Generar sus Pares de Claves Maestras:**
    ```bash
    ./bin/hsc_cli gen-keypair alice
    ./bin/hsc_cli gen-keypair bob
    ```
    *Esto crea `alice.key`, `alice.pub`, `bob.key` y `bob.pub`.*

3.  **(Alice y Bob) Generar Solicitudes de Firma de Certificado (CSRs):**
    ```bash
    ./bin/hsc_cli gen-csr alice.key "alice@example.com"
    ./bin/hsc_cli gen-csr bob.key "bob@example.com"
    ```
    *Esto crea `alice.csr` y `bob.csr`.*

4.  **(CA) Firmar los CSRs para Emitir Certificados:**
    *La CA utiliza su clave privada (`ca.key`) y certificado (`ca.pem`) para firmar los CSRs.*
    ```bash
    ./bin/test_ca_util sign alice.csr ca.key ca.pem alice.pem
    ./bin/test_ca_util sign bob.csr ca.key ca.pem bob.pem
    ```
    *Alice y Bob ahora tienen sus certificados oficiales, `alice.pem` y `bob.pem`.*

5.  **(Alice) Verifica el Certificado de Bob Antes de Enviar:**
    *Alice utiliza el certificado de CA de confianza (`ca.pem`) para verificar la identidad de Bob. Este es un paso crítico antes de confiar en su certificado.*
    ```bash
    ./bin/hsc_cli verify-cert bob.pem --ca ca.pem --user "bob@example.com"
    ```

6.  **(Alice) Cifra un Archivo para Bob:**
    *Alice ahora tiene varias opciones:*

    **Opción A: Basado en Certificado con Validación (Predeterminado Seguro y Recomendado)**
    > Esta es la forma estándar y segura de operar. La herramienta **requiere** que Alice proporcione el certificado de la CA y el nombre de usuario esperado para realizar una validación completa y estricta del certificado de Bob antes de cifrar.
    ```bash
    echo "This is top secret information." > secret.txt
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key --ca ca.pem --user "bob@example.com"
    ```

    **Opción B: Basado en Certificado sin Validación (Peligroso - Solo para Expertos)**
    > Si Alice está absolutamente segura de la autenticidad del certificado y desea omitir la validación, debe usar explícitamente la bandera `--no-verify`. **No se recomienda.**
    ```bash
    # ¡Usar con extrema precaución!
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key --no-verify
    ```

    **Opción C: Modo de Clave Directa (Avanzado - Para Claves Pre-confiadas)**
    *Si Alice ya ha obtenido la clave pública de Bob (`bob.pub`) a través de un canal seguro y de confianza, puede cifrar directamente con ella, omitiendo toda la lógica de certificados.*
    ```bash
    ./bin/hsc_cli encrypt secret.txt --recipient-pk-file bob.pub --from alice.key
    ```
    *Todas las opciones crean `secret.txt.hsc`. Alice ahora puede enviar `secret.txt.hsc` y su certificado `alice.pem` a Bob.*

7.  **(Bob) Descifra el Archivo al Recibirlo:**
    *Bob utiliza su clave privada (`bob.key`) para descifrar el archivo. Dependiendo de cómo Alice lo cifró, necesitará su certificado (`alice.pem`) o su clave pública sin procesar (`alice.pub`).*

    **Si Alice Usó la Opción A o B (Certificado):**
    ```bash
    ./bin/hsc_cli decrypt secret.txt.hsc --to bob.key --from alice.pem
    ```

    **Si Alice Usó la Opción C (Clave Directa):**
    ```bash
    ./bin/hsc_cli decrypt secret.txt.hsc --to bob.key --sender-pk-file alice.pub
    ```
    *Ambos comandos producirán `secret.txt.decrypted`.*
    ```bash
    cat secret.txt.decrypted
    ```

### 5.2 Uso como Biblioteca en su Proyecto

`src/main.c` sirve como un excelente ejemplo de integración. Un flujo de llamadas a la API típico es el siguiente:

1.  **Inicialización Global y Configuración de Registro:** Llame a `hsc_init()` al inicio y registre un callback de registro.
    ```c
    #include "hsc_kernel.h"
    #include <stdio.h>

    // Defina una función de registro simple para su aplicación
    void my_app_logger(int level, const char* message) {
        // Ejemplo: Imprimir errores en stderr, información en stdout
        if (level >= 2) { // 2 = ERROR
            fprintf(stderr, "[HSC_LIB_ERROR] %s\n", message);
        } else {
            printf("[HSC_LIB_INFO] %s\n", message);
        }
    }

    int main() {
        if (hsc_init() != HSC_OK) {
            // Manejar error fatal
        }
        // Registre su función de registro en la biblioteca
        hsc_set_log_callback(my_app_logger);

        // ... Su código ...
        hsc_cleanup();
        return 0;
    }
    ```

2.  **Remitente (Alice) Cifra Datos:**
    ```c
    // 1. Genere una clave de sesión de un solo uso
    unsigned char session_key[HSC_SESSION_KEY_BYTES];
    hsc_random_bytes(session_key, sizeof(session_key));

    // 2. Cifre los datos con la clave de sesión usando AEAD (para datos pequeños)
    const char* message = "Secret message";
    // ... (la lógica de cifrado es la misma que en el ejemplo) ...

    // 3. Verifique el certificado del destinatario (Bob)
    if (hsc_verify_user_certificate(bob_cert_pem, ca_pem, "bob@example.com") != HSC_OK) {
        // El certificado no es válido, ¡aborte! La biblioteca registrará detalles a través de su callback.
    }

    // 4. Extraiga la clave pública de Bob de su certificado
    unsigned char bob_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    if (hsc_extract_public_key_from_cert(bob_cert_pem, bob_pk) != HSC_OK) {
        // Manejar error de extracción
    }

    // 5. Encapsule la clave de sesión
    // ... (la lógica de encapsulación es la misma que en el ejemplo) ...
    ```

3.  **Receptor (Bob) Descifra Datos:**
    *La lógica de descifrado sigue siendo la misma, pero cualquier error interno durante la desencapsulación o el descifrado AEAD ahora se informará a través de su callback `my_app_logger` registrado en lugar de contaminar `stderr` directamente.*

## 6. Análisis Profundo: Arquitectura Técnica

El núcleo de este proyecto es un modelo de cifrado híbrido que combina las ventajas de la criptografía asimétrica y simétrica para lograr una transferencia de datos segura y eficiente.

**Flujo de Datos y Diagrama de Relación de Claves:**

```
REMITENTE (ALICE)                                        RECEPTOR (BOB)
========================================================================
[ Texto Plano ] --> Generar [ Clave de Sesión ]
                    |           |
(Cifrado Simétrico) <-'           '-> (Encapsulación Asimétrica) usando: Clave Pública de Bob, Clave Privada de Alice
      |                                   |
[ Datos Cifrados ]                    [ Clave de Sesión Encapsulada ]
      |                                   |
      '---------------------.   .-------------------'
                            |   |
                            v   v
                        [ Paquete de Datos ]
                            |
   ==================>  A través de Red/Archivo  =================>
                            |
                        [ Paquete de Datos ]
                            |   |
            .---------------'   '-----------------.
            |                                   |
[ Clave de Sesión Encapsulada ]       [ Datos Cifrados ]
            |                                   |
            v                                   |
(Desencapsulación Asimétrica) usando: Clave Privada de Bob, Clave Pública de Alice
            |                                   |
            v                                   |
       [ Clave de Sesión Recuperada ] <-$-----' (Descifrado Simétrico)
            |
            v
       [ Texto Plano ]
```

## 7. Configuración Avanzada: Mejorando la Seguridad con Variables de Entorno

Para adaptarse a futuras necesidades de hardware y seguridad sin modificar el código, este proyecto admite el **aumento** del costo computacional de la función de derivación de claves (Argon2id) a través de variables de entorno.

*   **`HSC_ARGON2_OPSLIMIT`**: Establece el número de operaciones (rondas computacionales) para Argon2id.
*   **`HSC_ARGON2_MEMLIMIT`**: Establece el uso de memoria en bytes para Argon2id.

**Nota de Seguridad Importante:** Esta función **solo se puede usar para fortalecer los parámetros de seguridad**. Si los valores establecidos en las variables de entorno son más bajos que las bases de seguridad mínimas incorporadas en el proyecto, el programa ignorará automáticamente los valores inseguros y aplicará los mínimos incorporados.

**Ejemplo de Uso:**

```bash
# Ejemplo: Aumentar el límite de operaciones a 10 y el límite de memoria a 512MB.
# Nota: HSC_ARGON2_MEMLIMIT requiere el valor en bytes.
# 512 * 1024 * 1024 = 536870912 bytes.
export HSC_ARGON2_OPSLIMIT=10
export HSC_ARGON2_MEMLIMIT=536870912

# Cualquier programa que se ejecute en un shell con estas variables establecidas utilizará automáticamente estos parámetros más fuertes.
./bin/hsc_cli gen-keypair my_strong_key
```

## 8. Tema Avanzado: Comparación de Modos de Cifrado

Oracipher Core proporciona dos flujos de trabajo de cifrado híbrido distintos, cada uno con diferentes garantías de seguridad. Elegir el correcto es fundamental.

### Flujo de Trabajo Basado en Certificados (Predeterminado y Recomendado)

*   **Cómo Funciona:** Utiliza certificados X.509 para vincular la identidad de un usuario (p. ej., `bob@example.com`) a su clave pública.
*   **Garantías de Seguridad:**
    *   **Autenticación:** Verifica criptográficamente que la clave pública pertenece realmente al destinatario previsto.
    *   **Integridad:** Asegura que el certificado no ha sido manipulado.
    *   **Comprobación de Revocación:** Comprueba activamente a través de OCSP si el certificado ha sido revocado por la autoridad emisora.
*   **Cuándo Usarlo:** En cualquier escenario donde el remitente y el receptor no tienen un canal preexistente y altamente seguro para intercambiar claves públicas. Este es el estándar para la mayoría de las comunicaciones basadas en Internet.

### Flujo de Trabajo de Clave Directa (sin procesar) (Avanzado)

*   **Cómo Funciona:** Omite toda la lógica de PKI y certificados, cifrando directamente a un archivo de clave pública sin procesar.
*   **Garantías de Seguridad:**
    *   Proporciona el mismo nivel de **confidencialidad** e **integridad** para los datos cifrados que el modo de certificado.
*   **Compromisos de Seguridad:**
    *   **Sin Autenticación:** Este modo **no** verifica la identidad del propietario de la clave. El usuario es el único responsable de garantizar la autenticidad de la clave pública que está utilizando. El uso de una clave pública incorrecta o maliciosa resultará en que los datos se cifren para la parte equivocada.
*   **Cuándo Usarlo:** Solo en sistemas cerrados o protocolos específicos donde las claves públicas se han intercambiado y verificado a través de un mecanismo fuera de banda independiente y de confianza (p. ej., claves integradas en el firmware de un dispositivo seguro o verificadas en persona).

## 9. Referencia de la API Principal (`include/hsc_kernel.h`)

### Inicialización y Limpieza
| Función | Descripción |
| :--- | :--- |
| `int hsc_init()` | **(Debe llamarse primero)** Inicializa toda la biblioteca. |
| `void hsc_cleanup()` | Llamar antes de que el programa termine para liberar recursos globales. |

### Gestión de Claves
| Función | Descripción |
| :--- | :--- |
| `hsc_master_key_pair* hsc_generate_master_key_pair()` | Genera un nuevo par de claves maestras. |
| `hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(...)` | Carga una clave privada desde un archivo. |
| `int hsc_save_master_key_pair(...)` | Guarda un par de claves en archivos. |
| `void hsc_free_master_key_pair(hsc_master_key_pair** kp)` | Libera de forma segura un par de claves maestras. |
| `int hsc_get_master_public_key(const hsc_master_key_pair* kp, ...)` | **[Nuevo]** Extrae la clave pública sin procesar de un manejador de par de claves. |

### PKI y Certificados
| Función | Descripción |
| :--- | :--- |
| `int hsc_generate_csr(...)` | Genera una Solicitud de Firma de Certificado (CSR) en formato PEM. |
| `int hsc_verify_user_certificate(...)` | **(Principal)** Realiza una validación completa del certificado (cadena, validez, sujeto, OCSP). |
| `int hsc_extract_public_key_from_cert(...)` | Extrae una clave pública de un certificado verificado. |

### Encapsulación de Claves (Asimétrico)
| Función | Descripción |
| :--- | :--- |
| `int hsc_encapsulate_session_key(...)` | Cifra una clave de sesión utilizando la clave pública del destinatario. |
| `int hsc_decapsulate_session_key(...)` | Descifra una clave de sesión utilizando la clave privada del destinatario. |

### Cifrado de Flujo (Simétrico, para archivos grandes)
| Función | Descripción |
| :--- | :--- |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(...)` | Crea un objeto de estado de flujo de cifrado. |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(...)` | Crea un objeto de estado de flujo de descifrado. |
| `int hsc_crypto_stream_push(...)` | Cifra un fragmento de datos en un flujo. |
| `int hsc_crypto_stream_pull(...)` | Descifra un fragmento de datos en un flujo. |
| `void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state)` | Libera un objeto de estado de flujo. |
| `int hsc_hybrid_encrypt_stream_raw(...)` | Realiza un cifrado híbrido completo en un archivo utilizando una clave pública sin procesar. |
| `int hsc_hybrid_decrypt_stream_raw(...)` | Realiza un descifrado híbrido completo en un archivo utilizando una clave pública sin procesar. |

### Cifrado de Datos (Simétrico, para datos pequeños)
| Función | Descripción |
| :--- | :--- |
| `int hsc_aead_encrypt(...)` | Realiza un cifrado autenticado en un **pequeño fragmento de datos** usando AEAD. |
| `int hsc_aead_decrypt(...)` | Descifra y verifica datos cifrados por `hsc_aead_encrypt`. |

### Memoria Segura
| Función | Descripción |
| :--- | :--- |
| `void* hsc_secure_alloc(size_t size)` | Asigna un bloque de memoria protegido y no intercambiable. |
| `void hsc_secure_free(void* ptr)` | Borra y libera de forma segura un bloque de memoria protegido. |

### Registro
| Función | Descripción |
| :--- | :--- |
| `void hsc_set_log_callback(hsc_log_callback callback)` | **[Nuevo]** Registra una función de callback para manejar todos los registros internos de la biblioteca. |

## 10. Contribuciones

¡Damos la bienvenida a todas las formas de contribución! Si encuentra un error, tiene una sugerencia de función o desea mejorar la documentación, no dude en enviar un Pull Request o crear un Issue.

## 11. Notas sobre Certificados

Este proyecto utiliza un sistema de certificados **X.509 v3** para vincular claves públicas con identidades de usuario (p. ej., `alice@example.com`), estableciendo así la confianza. El proceso de validación de certificados incluye la **validación de la cadena de firmas**, la **verificación del período de validez**, la **verificación de la identidad del sujeto** y la **comprobación del estado de revocación (OCSP)**, todo bajo una estricta política de "fallo cerrado".

## 12. Licencia - Modelo de Licencia Dual

Este proyecto se distribuye bajo un modelo de **licencia dual**:

### 1. Licencia Pública General Affero de GNU v3.0 (AGPLv3)
Esta licencia es adecuada para proyectos de código abierto, investigación académica y estudio personal. Requiere que cualquier trabajo derivado, ya sea modificado u ofrecido como un servicio a través de una red, también debe tener su código fuente completo disponible bajo la AGPLv3.

### 2. Licencia Comercial
Se debe obtener una licencia comercial para cualquier aplicación, producto o servicio comercial de código cerrado. Si no desea estar sujeto a los términos de código abierto de la AGPLv3, debe adquirir una licencia comercial.

**Para obtener una licencia comercial, por favor contacte a: `eldric520lol@gmail.com`**