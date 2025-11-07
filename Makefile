#
# Makefile for the High-Security Hybrid Encryption System
#

# --- Compiler and Flags ---
CC = gcc
# General flags: -g for debugging, -I to find headers, -Wall/-Wextra for all good warnings
CFLAGS = -g -I./src -Wall -Wextra -std=c11
# For Windows/MinGW, we disable AddressSanitizer as it can be tricky to configure.
# On Linux, you would add -fsanitize=address here.
TEST_CFLAGS = $(CFLAGS)
# Linker flags for all targets
LDFLAGS = -lsodium -lssl -lcrypto
# Linker flags for tests
TEST_LDFLAGS = $(LDFLAGS)


# --- Source Files ---
# Automatically find all .c files in the library source directories
LIB_SRCS = $(wildcard src/common/*.c) $(wildcard src/core_crypto/*.c) $(wildcard src/pki/*.c)
# Corresponding object files
LIB_OBJS = $(LIB_SRCS:.c=.o)


# --- Target: Main Application ---
APP_MAIN_SRC = src/main.c
APP_EXECUTABLE = high_security_app


# --- Target: Test Suites ---
# Automatically find all test files in the tests/ directory
TEST_SRCS = $(wildcard tests/*.c)
# Generate executable names from test source file names (e.g., tests/test_core.c -> test_core)
TEST_EXECUTABLES = $(patsubst tests/%.c, %, $(TEST_SRCS))


# --- Build Rules ---

# Default target when you just type 'make'
all: $(APP_EXECUTABLE)

# Rule to build the main application executable
$(APP_EXECUTABLE): $(LIB_OBJS) $(APP_MAIN_SRC)
	@echo "Linking main application: $@"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# A special "meta-target" for all tests
build_tests: $(TEST_EXECUTABLES)

# A generic pattern rule to build any test executable.
$(TEST_EXECUTABLES): % : $(LIB_OBJS) tests/%.c
	@echo "Linking test executable: $@"
	$(CC) $(TEST_CFLAGS) -o $@ $^ $(TEST_LDFLAGS)

# Generic pattern rule for compiling any .c source file into a .o object file
%.o: %.c
	@echo "Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@


# --- Commands ---

# The main command to run all tests.
test: build_tests
	@echo "\n--- Running all test suites ---"
	@for test_exe in $(TEST_EXECUTABLES); do \
		echo "[RUNNING] ./$$test_exe"; \
		./$$test_exe; \
	done
	@echo "--- All test suites finished ---\n"


# Clean up all build artifacts
clean:
	@echo "Cleaning up..."
	rm -f $(LIB_OBJS) $(APP_EXECUTABLE) $(TEST_EXECUTABLES)

# Declare targets that are not actual files
.PHONY: all test build_tests clean