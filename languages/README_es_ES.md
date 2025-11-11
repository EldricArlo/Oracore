<div align="center">
  <img src="../src/media/icon-256.png" alt="Oracipher Icon" width="128">
  <h1 style="border-bottom: none;">Oracipher Core</h1>

# Biblioteca de Kernel de Cifrado Híbrido de Alta Seguridad

| Build | Licencia | Lenguaje | Dependencias |
| :---: | :---: | :---: | :---: |
| ![Build Status](https://img.shields.io/badge/build-passing-brightgreen) | ![License](https://img.shields.io/badge/license-Dual--Licensed-blue) | ![Language](https://img.shields.io/badge/language-C11-purple) | ![Libsodium](https://img.shields.io/badge/libsodium-v1.0.18+-brightgreen) ![OpenSSL](https://img.shields.io/badge/OpenSSL-v3.0+-0075A8) ![Libcurl](https://img.shields.io/badge/libcurl-v7.68+-E5522D) |

</div>

## 1. 😎 Visión del Proyecto y Principios Fundamentales

Este proyecto es una biblioteca de kernel de cifrado híbrido avanzada, implementada en el estándar C11 y centrada en la seguridad. Su objetivo es proporcionar un plan de acción probado en batalla que demuestre cómo combinar bibliotecas de criptografía líderes en la industria (**libsodium**, **OpenSSL**, **libcurl**) en una solución de cifrado de extremo a extremo robusta, fiable y fácil de usar.

Nuestro diseño sigue los siguientes principios de seguridad fundamentales:

*   🥸 **Elegir Criptografía Moderna y Auditada:** Nunca implementar algoritmos de cifrado por cuenta propia. Usar solo primitivas criptográficas modernas, reconocidas por la comunidad y resistentes a ataques de canal lateral.
*   🤠 **Defensa en Profundidad:** La seguridad no depende de una sola capa. La defensa se construye en múltiples niveles, desde la gestión de memoria y el diseño de la API hasta el flujo del protocolo.
*   🙃 **Valores Predeterminados Seguros y "Fail-Closed" (Fallo Seguro):** El comportamiento predeterminado del sistema debe ser seguro. Al encontrar un estado incierto (como la incapacidad de verificar el estado de revocación de un certificado), el sistema debe optar por fallar y terminar la operación (Fail-Closed), en lugar de continuar la ejecución.
*   🫥 **Minimizar la Exposición de Datos Sensibles:** El ciclo de vida, el alcance y el tiempo de residencia en memoria de datos críticos como las claves privadas deben ser estrictamente controlados al mínimo absoluto necesario.

## 2. 🥲 Características Principales

*   😮 **Modelo de Cifrado Híbrido Robusto:**
    *   **Cifrado Simétrico:** Proporciona cifrado de flujo AEAD basado en **XChaCha20-Poly1305** para grandes bloques de datos y cifrado AEAD de un solo uso para pequeños bloques de datos.
    *   **Cifrado Asimétrico:** Utiliza **X25519** (basado en Curve25519) para la encapsulación de la clave de sesión simétrica, asegurando que solo el destinatario previsto pueda descifrarla.

*   🫨 **Pila de Primitivas Criptográficas Modernas:**
    *   **Derivación de Clave:** Adopta **Argon2id**, el ganador del Concurso de Hashing de Contraseñas, que resiste eficazmente los ataques de GPU y ASIC.
    *   **Firma Digital:** Emplea **Ed25519**, que ofrece capacidades de firma digital de alta velocidad y alta seguridad.
    *   **Unificación de Claves:** Utiliza ingeniosamente la característica de que las claves Ed25519 se pueden convertir de forma segura en claves X25519, lo que permite que un único par de claves maestras satisfaga tanto las necesidades de firma como de cifrado.

*   😏 **Soporte Integral para Infraestructura de Clave Pública (PKI):**
    *   **Ciclo de Vida del Certificado:** Soporta la generación de Solicitudes de Firma de Certificado (CSR) conformes con el estándar X.509 v3.
    *   **Validación Rigurosa de Certificados:** Ofrece un proceso de validación de certificados estandarizado, que incluye cadena de confianza, período de validez y coincidencia de sujeto.
    *   **Comprobación Obligatoria de Revocación (OCSP):** Verificación estricta incorporada del Protocolo de Estado de Certificados en Línea (OCSP) con una política de "fallo seguro", interrumpiendo inmediatamente la operación si no se puede confirmar el buen estado del certificado.

*   🧐 **Seguridad de Memoria Sólida como una Roca:**
    *   Expone las funciones de memoria segura de `libsodium` a través de una API pública, permitiendo a los clientes manejar datos sensibles (como claves de sesión) de forma segura.
    *   Todas las claves privadas internas se almacenan en memoria bloqueada, **evitando que el sistema operativo las intercambie al disco**, y se borran de forma segura antes de ser liberadas.

*   😵‍💫 **Prácticas de Ingeniería de Alta Calidad:**
    *   **Límites Claros de la API:** Proporciona un único archivo de cabecera público, `hsc_kernel.h`, que utiliza punteros opacos para encapsular todos los detalles de implementación interna, logrando una alta cohesión y un bajo acoplamiento.
    *   **Probado Unitariamente:** Incluye un conjunto de pruebas unitarias que cubren las funcionalidades principales de criptografía y PKI, asegurando la corrección y fiabilidad del código.
    *   **Documentación y Ejemplos Completos:** Proporciona un `README.md` detallado, así como un programa de demostración y una herramienta de línea de comandos listos para ejecutar.

## 3. 🤓 Estructura del Proyecto

El proyecto adopta una estructura de directorios clara y en capas para lograr la separación de responsabilidades.

```
.
├── include/
│   └── hsc_kernel.h      # [NÚCLEO] Único encabezado de API público
├── src/                  # Código fuente
│   ├── common/           # Módulos internos comunes (memoria segura, especificaciones de seguridad)
│   ├── core_crypto/      # Módulos internos de criptografía (envoltorio de libsodium)
│   ├── pki/              # Módulos internos de PKI (envoltorios de OpenSSL, libcurl)
│   ├── hsc_kernel.c      # [NÚCLEO] Implementación de la API pública
│   ├── main.c            # Ejemplo de uso de la API: Programa de demostración de flujo de extremo a extremo
│   └── cli.c             # Ejemplo de uso de la API: Potente herramienta de línea de comandos
├── tests/                # Pruebas unitarias
│   ├── test_*.c          # Pruebas unitarias para varios módulos
│   └── test_helpers.h/.c # Funciones auxiliares de prueba
├── Makefile              # Script de construcción y gestión de tareas
└── README.md             # Documentación de este proyecto
```

## 4. 🤥 Guía de Inicio Rápido

### 4.1. Dependencias del Entorno

*   **Herramientas de Construcción:** `make`
*   **Compilador de C:** `gcc` o `clang` (con soporte para el estándar C11)
*   **libsodium:** (`libsodium-dev`)
*   **OpenSSL:** Recomendado **v3.0** o superior (`libssl-dev`)
*   **libcurl:** (`libcurl4-openssl-dev`)

**Instalación con un solo comando en Debian/Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install build-essential libsodium-dev libssl-dev libcurl4-openssl-dev
```

### 4.2. Compilación y Pruebas

1.  **Compilar todos los objetivos (biblioteca, demo, CLI, pruebas):**
    ```bash
    make all
    ```

2.  **Ejecutar las pruebas unitarias (paso crucial):**
    ```bash
    make run-tests
    ```
    > 😝 **Nota sobre el comportamiento esperado de la prueba OCSP**
    >
    > Un caso de prueba en `test_pki_verification` utilizará intencionadamente un certificado que apunta a un servidor OCSP inválido para la verificación. Como la solicitud de red fallará inevitablemente, la función `hsc_verify_user_certificate` **debe** devolver `-4` para indicar un fallo en la comprobación del estado de revocación. El código de prueba afirmará que el valor de retorno es, de hecho, `-4`, demostrando así que nuestro mecanismo de seguridad "fail-closed" funciona correctamente.

3.  **Ejecutar el programa de demostración:**
    ```bash
    ./bin/hsc_demo
    ```

4.  **Ejecutar la herramienta de línea de comandos:**
    ```bash
    ./bin/hsc_cli --help
    ```

5.  **Limpiar los archivos de construcción:**
    ```bash
    make clean
    ```

## 5. ☺️ Guía de Uso

### 5.1. Como Herramienta de Línea de Comandos (`hsc_cli`)

`hsc_cli` es una herramienta de línea de comandos con todas las funciones, **que admite un orden de parámetros flexible**, para realizar todas las operaciones principales de criptografía y PKI.

**Ejemplo de flujo de trabajo completo: Alicia cifra un archivo y lo envía de forma segura a Roberto**

1.  **😒 (Ambas partes) Generar pares de claves maestras:**
    ```bash
    ./bin/hsc_cli gen-keypair alice
    ./bin/hsc_cli gen-keypair bob
    ```

2.  **☺️ (Ambas partes) Generar CSR y obtener certificados:** (Aquí se asume que una CA ya ha emitido `alice.pem` y `bob.pem`)
    ```bash
    ./bin/hsc_cli gen-csr alice.key "alice@example.com"
    # (Enviar alice.csr a la CA para obtener alice.pem)
    ```

3.  **🤨 (Alicia) Verificar el certificado de Roberto:** (Suponiendo que `ca.pem` es el certificado de la CA raíz de confianza)
    ```bash
    ./bin/hsc_cli verify-cert bob.pem --ca ca.pem --user "bob@example.com"
    ```
    > **Consejo:** Las opciones con valores (como `--ca` y `--user`) ahora se pueden listar en cualquier orden.

4.  **😑 (Alicia) Cifrar un archivo para Roberto:**
    ```bash
    echo "This is top secret information." > secret.txt
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key
    ```
    Ahora Alicia puede enviar `secret.hsc` y su propio certificado `alice.pem` a Roberto.

5.  **😉 (Roberto) Descifrar el archivo al recibirlo:**
    ```bash
    # Roberto también puede intercambiar el orden de --from y --to
    ./bin/hsc_cli decrypt secret.hsc --to bob.key --from alice.pem
    cat secret.decrypted
    ```

### 5.2. Integración como Biblioteca en su Proyecto

El archivo `src/main.c` es un excelente ejemplo de integración. A continuación, se muestra el flujo típico de llamadas a la API:

1.  **Inicialización Global:** Al iniciar el programa, llamar a `hsc_init()`.
    ```c
    #include "hsc_kernel.h"
    
    int main() {
        if (hsc_init() != 0) {
            // Manejar error fatal
        }
        // ... su código ...
        hsc_cleanup();
        return 0;
    }
    ```

2.  **Remitente (Alicia) Cifrando Datos:**
    ```c
    // 1. Generar una clave de sesión de un solo uso
    unsigned char session_key[HSC_SESSION_KEY_BYTES];
    randombytes_buf(session_key, sizeof(session_key));

    // 2. Cifrar datos con la clave de sesión usando AEAD (adecuado para datos pequeños)
    const char* message = "Secret message";
    size_t enc_buf_size = strlen(message) + HSC_AEAD_NONCE_BYTES + HSC_AEAD_TAG_BYTES;
    unsigned char* encrypted_data = malloc(enc_buf_size);
    unsigned long long encrypted_data_len;
    hsc_aead_encrypt(encrypted_data, &encrypted_data_len, 
                     (const unsigned char*)message, strlen(message), session_key);

    // 3. Verificar el certificado del destinatario (Roberto)
    if (hsc_verify_user_certificate(bob_cert_pem, ca_pem, "bob@example.com") != 0) {
        // ¡Certificado inválido, abortar!
    }

    // 4. Extraer la clave pública de Roberto de su certificado
    unsigned char bob_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    hsc_extract_public_key_from_cert(bob_cert_pem, bob_pk);

    // 5. Encapsular la clave de sesión usando la clave pública de Roberto y la clave privada de Alicia
    // (Suponiendo que alice_kp es un hsc_master_key_pair* cargado)
    unsigned char encapsulated_key[...]; size_t encapsulated_key_len;
    hsc_encapsulate_session_key(encapsulated_key, &encapsulated_key_len, 
                                session_key, sizeof(session_key),
                                bob_pk, alice_kp);
    
    // 6. Enviar encrypted_data y encapsulated_key a Roberto
    ```

3.  **Destinatario (Roberto) Descifrando Datos:**
    ```c
    // 1. Extraer la clave pública del remitente (Alicia) de su certificado
    unsigned char alice_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    hsc_extract_public_key_from_cert(alice_cert_pem, alice_pk);
    
    // 2. Desencapsular la clave de sesión usando la clave pública de Alicia y la clave privada de Roberto
    // (Suponiendo que bob_kp es un hsc_master_key_pair* cargado)
    unsigned char* dec_session_key = hsc_secure_alloc(HSC_SESSION_KEY_BYTES);
    if (hsc_decapsulate_session_key(dec_session_key, encapsulated_key, enc_key_len,
                                    alice_pk, bob_kp) != 0) {
        // ¡Fallo en la desencapsulación!
    }

    // 3. Descifrar los datos usando la clave de sesión recuperada
    unsigned char final_message[...]; unsigned long long final_len;
    if (hsc_aead_decrypt(final_message, &final_len,
                         encrypted_data, encrypted_data_len, dec_session_key) != 0) {
        // ¡Fallo en el descifrado! Los datos han sido manipulados
    }

    // 4. Liberar de forma segura la clave de sesión después de su uso
    hsc_secure_free(dec_session_key);
    ```

## 6. 😶 Análisis Profundo de la Arquitectura Técnica

El núcleo de este proyecto es el modelo de Cifrado Híbrido, que combina las ventajas del cifrado asimétrico y simétrico para lograr una transmisión de datos segura y eficiente.

**Diagrama de Flujo de Datos y Relación de Claves:**

```
REMITENTE (ALICIA)                                       DESTINATARIO (ROBERTO)
================================================================================
[Datos Originales] -> Genera [Clave de Sesión]
                      |        |
(Cifrado Simétrico) <--------'        '-> (Encapsulación Asimétrica) Usando: Clave Pública de Roberto, Clave Privada de Alicia
       |                                      |
[Datos Cifrados]                      [Clave de Sesión Encapsulada]
       |                                      |
       '----------------. .-------------------'
                        | |
                        v v
                    [Paquete de Transmisión]
                         |
     ==================> | Red/Transferencia de Archivos =================>
                         |
                    [Paquete de Transmisión]
                        | |
             .----------' '-------------.
             |                          |
[Clave de Sesión Encapsulada]      [Datos Cifrados]
             |                          |
             v                          |
(Desencapsulación Asimétrica) Usando: Clave Privada de Roberto, Clave Pública de Alicia |
             |                          |
             v                          |
        [Clave de Sesión Recuperada] <-$----' (Descifrado Simétrico)
             |
             v
        [Datos Originales]
```

## 7. 😄 Configuración Avanzada: Mejorando la Seguridad con Variables de Entorno

Para adaptarse a hardware y requisitos de seguridad futuros más exigentes sin modificar el código, este proyecto admite **aumentar** la fuerza computacional de la función de derivación de clave (Argon2id) a través de variables de entorno.

*   **`HSC_ARGON2_OPSLIMIT`**: Establece el número de iteraciones (computacionales) para Argon2id.
*   **`HSC_ARGON2_MEMLIMIT`**: Establece el uso de memoria para Argon2id (en bytes).

**Nota de Seguridad Importante:** Esta funcionalidad **solo se puede usar para aumentar los parámetros de seguridad**. Si los valores establecidos en las variables de entorno son inferiores a la línea base de seguridad mínima incorporada en el proyecto, el programa ignorará automáticamente estos valores inseguros y forzará el uso de los mínimos incorporados.

** Nuevo Ejemplo de Uso:**

```bash
# Ejemplo: Aumentar el límite de operaciones a 10 y el límite de memoria a 512MB.
# Nota: HSC_ARGON2_MEMLIMIT necesita estar en bytes.
# 512 * 1024 * 1024 = 536870912 bytes.
export HSC_ARGON2_OPSLIMIT=10
export HSC_ARGON2_MEMLIMIT=536870912

# Ejecutar el programa en un shell donde las variables de entorno están definidas.
# Utilizará automáticamente estos parámetros más fuertes.
./bin/hsc_cli gen-keypair my_strong_key
```

## 8. 😀 Referencia Principal de la API (`include/hsc_kernel.h`)

### Inicialización y Limpieza
| Función | Descripción |
| :--- | :--- |
| `int hsc_init()` | **(Debe llamarse primero)** Inicializa toda la biblioteca. |
| `void hsc_cleanup()` | Se llama antes de que el programa salga para liberar recursos globales. |

### Gestión de Claves
| Función | Descripción |
| :--- | :--- |
| `hsc_master_key_pair* hsc_generate_master_key_pair()` | Genera un nuevo par de claves maestras. |
| `hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(...)` | Carga una clave privada desde un archivo. |
| `int hsc_save_master_key_pair(...)` | Guarda un par de claves en un archivo. |
| `void hsc_free_master_key_pair(hsc_master_key_pair** kp)` | Libera de forma segura un par de claves maestras. |

### PKI y Certificados
| Función | Descripción |
| :--- | :--- |
| `int hsc_generate_csr(...)` | Genera una Solicitud de Firma de Certificado (CSR) en formato PEM. |
| `int hsc_verify_user_certificate(...)` | **(Central)** Realiza la validación completa del certificado (cadena, validez, sujeto, OCSP). |
| `int hsc_extract_public_key_from_cert(...)` | Extrae una clave pública de un certificado verificado. |

### Encapsulación de Claves (Asimétrico)
| Función | Descripción |
| :--- | :--- |
| `int hsc_encapsulate_session_key(...)` | Cifra una clave de sesión usando la clave pública del destinatario. |
| `int hsc_decapsulate_session_key(...)` | Descifra una clave de sesión usando la clave privada del destinatario. |

### Cifrado de Datos (Simétrico)
| Función | Descripción |
| :--- | :--- |
| `int hsc_aead_encrypt(...)` | Cifra y autentica un **pequeño bloque de datos** usando AEAD. |
| `int hsc_aead_decrypt(...)` | Descifra y verifica datos cifrados por `hsc_aead_encrypt`. |

### Cifrado de Flujo (Simétrico, para archivos grandes)
| Función | Descripción |
| :--- | :--- |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(...)` | Crea un objeto de estado de flujo de cifrado. |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(...)` | Crea un objeto de estado de flujo de descifrado. |
| `int hsc_crypto_stream_push(...)` | Cifra un bloque de datos en el flujo. |
| `int hsc_crypto_stream_pull(...)` | Descifra un bloque de datos del flujo. |
| `void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state)` | Libera el objeto de estado del flujo. |

### Memoria Segura
| Función | Descripción |
| :--- | :--- |
| `void* hsc_secure_alloc(size_t size)` | Asigna un bloque de memoria protegida y no paginable. |
| `void hsc_secure_free(void* ptr)` | Borra y libera de forma segura la memoria protegida. |


## 9. 🥳 Contribuciones

¡Damos la bienvenida a contribuciones de todo tipo! Si encuentras un error, tienes una sugerencia de funcionalidad o quieres mejorar la documentación, no dudes en enviar un Pull Request o crear un Issue.

## 10. 🥺 Descripción del Certificado

Este proyecto utiliza el sistema de certificados **X.509 v3** para vincular una clave pública a una identidad de usuario (como `alice@example.com`), estableciendo así la confianza. El proceso de validación del certificado incluye la **validación de la cadena de firmas**, la **comprobación de la validez**, la **verificación de la identidad del sujeto** y la **comprobación del estado de revocación (OCSP)**, adoptando una estricta política de "fallo seguro".

## 11. 🥸 Licencia - Modelo de Doble Licencia

Este proyecto adopta un modelo de **Doble Licencia (Dual-License)**:

### 1. GNU Affero General Public License v3.0 (AGPLv3)
Adecuado para proyectos de código abierto, investigación académica y aprendizaje personal. Requiere que cualquier trabajo derivado modificado o puesto a disposición a través de una red también deba abrir su código fuente completo bajo la AGPLv3.

### 2. Licencia Comercial
Adecuado para cualquier aplicación, producto o servicio comercial de código cerrado. Si no desea estar sujeto a los términos de código abierto de la AGPLv3, debe obtener una licencia comercial.

**Para obtener una licencia comercial, póngase en contacto con: `eldric520lol@gmail.com`**