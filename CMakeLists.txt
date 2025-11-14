# ==============================================================================
# CMakeLists.txt for Oracipher Core
#
# Prepared by the Oracipher Core Code Review Committee
# Version: 1.1 (pkg-config compatible for MSYS2/Linux)
#
# This file provides a modern, cross-platform build system for the project,
# replacing the traditional Makefile.
# ==============================================================================

# --- 1. Project Definition and C Standard ---
# Set the minimum required CMake version. 3.12 is a reasonable baseline.
cmake_minimum_required(VERSION 3.12)

# Define the project name, version, and language.
project(OracipherCore VERSION 1.0 LANGUAGES C)

# Enforce the C11 standard strictly, as required by the project specification.
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)


# --- 2. Compiler Settings and Warnings ---
# Set Position Independent Code (PIC) property, which is necessary for shared libraries.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Apply strict compiler warnings for high code quality, as specified in the review baseline.
if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_CLANG)
    add_compile_options(-Wall -Wextra -Werror)
endif()


# --- 3. Dependency Discovery (Using pkg-config for MSYS2/Linux compatibility) ---
# First, find the pkg-config tool itself.
find_package(PkgConfig REQUIRED)

# Use pkg_check_modules to find libraries via pkg-config. This is the standard
# way to find libraries in environments like MSYS2 and Linux.
# The command will create variables like <PREFIX>_INCLUDE_DIRS and <PREFIX>_LIBRARIES.
pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(CURL REQUIRED libcurl)

message(STATUS "Found Libsodium via pkg-config")
message(STATUS "Found OpenSSL via pkg-config")
message(STATUS "Found Libcurl via pkg-config")


# --- 4. Define the Core Shared Library (`hsc_kernel`) ---
# Automatically discover all source files for the kernel library.
file(GLOB_RECURSE KERNEL_SRCS
    "src/common/*.c"
    "src/core_crypto/*.c"
    "src/pki/*.c"
    "src/hsc_kernel.c"
)

# Create the shared library target.
add_library(hsc_kernel SHARED ${KERNEL_SRCS})

# Define the public include directory. Any target linking against hsc_kernel
# will automatically get this include path.
target_include_directories(hsc_kernel PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include> # Path after installation
)

# Add the private include directories discovered by pkg-config.
target_include_directories(hsc_kernel PRIVATE
    ${SODIUM_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
)

# Link the core library against its dependencies using the variables from pkg-config.
target_link_libraries(hsc_kernel PUBLIC
    ${SODIUM_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${CURL_LIBRARIES}
)


# --- 5. Define Executable Targets ---
# The command-line interface tool.
add_executable(hsc_cli src/cli.c)
target_link_libraries(hsc_cli PRIVATE hsc_kernel)

# The demonstration program.
add_executable(hsc_demo src/main.c)
target_link_libraries(hsc_demo PRIVATE hsc_kernel)

# The standalone Test CA utility. It does not link against our kernel library,
# but it does require the external dependencies.
add_executable(test_ca_util tests/test_ca_util.c)

# The standalone Test CA utility also needs the include paths and libraries.
target_include_directories(test_ca_util PRIVATE
    ${SODIUM_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
)
target_link_libraries(test_ca_util PRIVATE
    ${SODIUM_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${CURL_LIBRARIES}
)


# --- 6. Define Test Suite ---
# Enable testing with CTest, CMake's testing framework.
enable_testing()
include(CTest)

# Find the test helper source files.
file(GLOB TEST_HELPER_SRCS "tests/test_helpers.c")

# Find all test entry point files (e.g., test_*.c)
file(GLOB TEST_MAIN_SRCS "tests/test_*.c")

# Exclude helper files and the standalone CA utility from the main test list.
list(REMOVE_ITEM TEST_MAIN_SRCS
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_helpers.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ca_util.c"
)

# Iterate over each found test file, create an executable for it, and register it as a test.
foreach(test_source ${TEST_MAIN_SRCS})
    # Get a clean name for the target from the filename (e.g., "test_pki_verification").
    get_filename_component(test_name ${test_source} NAME_WE)

    # Create an executable for this specific test.
    add_executable(${test_name} ${test_source} ${TEST_HELPER_SRCS})

    # Link the test executable against our kernel library.
    target_link_libraries(${test_name} PRIVATE hsc_kernel)

    # Add this executable to the CTest test suite.
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()


# --- 7. Installation Rules ---
# Define rules for installing the library, headers, and executables.
# This allows for easy packaging or system-wide installation via `cmake --install`.
message(STATUS "Configuring installation rules...")

# Define output directories for binaries and libraries.
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Install the library, executables, and public header file to standard locations.
install(TARGETS hsc_kernel hsc_cli hsc_demo test_ca_util
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
install(FILES include/hsc_kernel.h DESTINATION include)

message(STATUS "CMake configuration complete. You can now build with 'cmake --build .'")