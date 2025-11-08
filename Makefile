#
# Makefile for the High-Security Hybrid Encryption System
# [最终修订版 by the Code Review Committee]
#

# --- Compiler and Flags ---
CC = gcc
# CFLAGS: -g for debug, -I for include paths, Wall/Wextra for warnings, std=c11 for standard
# -MMD -MP for auto dependency generation
# -DWIN32_LEAN_AND_MEAN -DNOCRYPT for Windows compatibility with OpenSSL
# [核心修改] 将 include 路径扩展到 tests/ 目录，以支持 test_helpers.h
CFLAGS = -g -I./src -I./tests -Wall -Wextra -std=c11 -MMD -MP -DWIN32_LEAN_AND_MEAN -DNOCRYPT

# --- Libraries ---
# Common libraries needed for linking applications and tests
LDFLAGS = -lsodium -lssl -lcrypto -lcurl

# --- Directories and Paths ---
# [委员会改进] 将所有输出统一管理到 bin/ 目录
BIN_DIR = bin
SRC_DIR = src
TEST_DIR = tests

# --- Source & Object Files Discovery ---
# [委员会改进] 自动发现所有模块的源文件
LIB_SRCS = $(wildcard $(SRC_DIR)/common/*.c) $(wildcard $(SRC_DIR)/core_crypto/*.c) $(wildcard $(SRC_DIR)/pki/*.c)
LIB_OBJS = $(LIB_SRCS:.c=.o)

# Main application files
APP_MAIN_SRC = $(SRC_DIR)/main.c
APP_MAIN_OBJ = $(APP_MAIN_SRC:.c=.o)
APP_EXECUTABLE = $(BIN_DIR)/high_security_app

# CLI application files
CLI_MAIN_SRC = $(SRC_DIR)/cli.c
CLI_MAIN_OBJ = $(CLI_MAIN_SRC:.c=.o)
CLI_EXECUTABLE = $(BIN_DIR)/hsc_cli

# [委员会核心改进] 自动发现所有测试文件并生成对应的可执行文件路径
# 这将匹配 tests/test_*.c 和 tests/*_test.c 等所有文件
TEST_SRCS = $(wildcard $(TEST_DIR)/test_*.c) $(wildcard $(TEST_DIR)/*_test.c)
# [核心修改] 从测试源文件中排除辅助模块，因为它不是一个独立的可执行测试
TEST_SRCS := $(filter-out $(TEST_DIR)/test_helpers.c, $(TEST_SRCS))
TEST_OBJS = $(TEST_SRCS:.c=.o)
TEST_EXECUTABLES = $(patsubst $(TEST_DIR)/%.c,$(BIN_DIR)/%,$(TEST_SRCS))

# [核心修改] 自动发现并管理共享的测试辅助模块
TEST_HELPER_SRCS = $(wildcard $(TEST_DIR)/test_helpers.c)
TEST_HELPER_OBJS = $(TEST_HELPER_SRCS:.c=.o)

# [核心修改] 更新所有对象文件列表，以包含新的测试辅助模块
# List of all object files for dependency tracking
ALL_OBJS = $(LIB_OBJS) $(APP_MAIN_OBJ) $(CLI_MAIN_OBJ) $(TEST_OBJS) $(TEST_HELPER_OBJS)
DEPS = $(ALL_OBJS:.o=.d)


# --- Build Rules ---

.PHONY: all test build_tests clean

# [委员会改进] 'all' 目标现在依赖于 bin 目录的创建，并构建所有应用
all: $(BIN_DIR) $(APP_EXECUTABLE) $(CLI_EXECUTABLE)

# Rule to create the bin directory if it doesn't exist
$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Linking rule for the main application
$(APP_EXECUTABLE): $(APP_MAIN_OBJ) $(LIB_OBJS) | $(BIN_DIR)
	@echo "Linking main application: $@"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Linking rule for the CLI application
$(CLI_EXECUTABLE): $(CLI_MAIN_OBJ) $(LIB_OBJS) | $(BIN_DIR)
	@echo "Linking CLI application: $@"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Main target to build all test executables
build_tests: $(TEST_EXECUTABLES)

# [核心修改] 更新静态模式规则，将 test_helpers.o 链接到每一个测试可执行文件中
# 例如: 'bin/test_symmetric_crypto' 依赖于 'tests/test_symmetric_crypto.o', 所有库对象, 以及所有测试辅助对象
$(TEST_EXECUTABLES): $(BIN_DIR)/% : $(TEST_DIR)/%.o $(LIB_OBJS) $(TEST_HELPER_OBJS) | $(BIN_DIR)
	@echo "Linking test executable: $@"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Generic rule for compiling any .c file to a .o file, regardless of its location
# [核心修改] 明确指定了 include 路径，以确保编译器能找到所有头文件
%.o: %.c
	@echo "Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@


# --- Commands ---

# [委员会改进] 'test' 目标现在自动运行所有已构建的测试可执行文件
test: build_tests
	@echo "\n--- Running all test suites ---"
	@for test_exe in $(TEST_EXECUTABLES); do \
		echo "[RUNNING] ./$$test_exe"; \
		./$$test_exe; \
		if [ $$? -ne 0 ]; then \
			echo "!!! TEST FAILED: $$test_exe !!!"; \
			exit 1; \
		fi; \
	done
	@echo "--- All test suites finished successfully ---\n"

# [委员会改进] 更彻底的清理规则
clean:
	@echo "Cleaning up..."
	rm -rf $(BIN_DIR)
	find . -type f -name "*.o" -delete
	find . -type f -name "*.d" -delete

# Include automatically generated dependency files
-include $(DEPS)