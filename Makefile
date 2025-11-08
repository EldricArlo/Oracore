#
# Makefile for the High-Security Hybrid Encryption System
# [REVISED by the Code Review Committee - FINAL FIX for Windows]
#

# --- Compiler and Flags ---
CC = gcc

# [MODIFIED] Added -DWIN32_LEAN_AND_MEAN and -DNOCRYPT to CFLAGS.
# This is the definitive fix for naming conflicts between OpenSSL and
# Windows system headers (wincrypt.h) when compiling on Windows.
CFLAGS = -g -I./src -Wall -Wextra -std=c11 -MMD -MP -DWIN32_LEAN_AND_MEAN -DNOCRYPT

TEST_CFLAGS = $(CFLAGS)
LDFLAGS = -lsodium -lssl -lcrypto -lcurl
TEST_LDFLAGS = $(LDFLAGS)


# --- Source Files & Object Files ---
LIB_SRCS = $(wildcard src/common/*.c) $(wildcard src/core_crypto/*.c) $(wildcard src/pki/*.c)
LIB_OBJS = $(LIB_SRCS:.c=.o)

APP_MAIN_SRC = src/main.c
APP_MAIN_OBJ = $(APP_MAIN_SRC:.c=.o)
APP_EXECUTABLE = high_security_app

# Define source, object, and executable for the new CLI tool
CLI_MAIN_SRC = src/cli.c
CLI_MAIN_OBJ = $(CLI_MAIN_SRC:.c=.o)
CLI_EXECUTABLE = hsc_cli

TEST_SRCS = $(wildcard tests/*.c)
TEST_OBJS = $(TEST_SRCS:.c=.o)
TEST_EXECUTABLES = $(patsubst tests/%.c, %, $(TEST_SRCS))

# [MODIFIED] Add the CLI object file to the list of all objects for cleaning
ALL_OBJS = $(LIB_OBJS) $(APP_MAIN_OBJ) $(TEST_OBJS) $(CLI_MAIN_OBJ)
DEPS = $(ALL_OBJS:.o=.d)


# --- Build Rules ---
# [MODIFIED] The 'all' target now builds both the demo app and the CLI tool
all: $(APP_EXECUTABLE) $(CLI_EXECUTABLE)

$(APP_EXECUTABLE): $(LIB_OBJS) $(APP_MAIN_OBJ)
	@echo "Linking main application: $@"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Add the build rule for our new CLI executable
$(CLI_EXECUTABLE): $(LIB_OBJS) $(CLI_MAIN_OBJ)
	@echo "Linking CLI application: $@"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

build_tests: $(TEST_EXECUTABLES)

$(TEST_EXECUTABLES): % : $(LIB_OBJS) tests/%.o
	@echo "Linking test executable: $@"
	$(CC) $(TEST_CFLAGS) -o $@ $^ $(TEST_LDFLAGS)

%.o: %.c
	@echo "Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@


# --- Commands ---
test: build_tests
	@echo "\n--- Running all test suites ---"
	@for test_exe in $(TEST_EXECUTABLES); do \
		echo "[RUNNING] ./$$test_exe"; \
		./$$test_exe; \
	done
	@echo "--- All test suites finished ---\n"

clean:
	@echo "Cleaning up..."
	# [MODIFIED] Add the CLI executable to the list of files to be removed
	rm -f $(ALL_OBJS) $(DEPS) $(APP_EXECUTABLE) $(TEST_EXECUTABLES) $(CLI_EXECUTABLE)

.PHONY: all test build_tests clean

-include $(DEPS)