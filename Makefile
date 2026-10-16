CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -g -O2 -Isrc -Wno-deprecated-declarations
LDFLAGS = -L/usr/local/lib -lssl -lcrypto -lsecp256k1

# Source directory
SRCDIR = src

# Find all C files in src directory, excluding anvil_fuzzer.c
SOURCES = $(filter-out $(SRCDIR)/anvil_fuzzer.c, $(wildcard $(SRCDIR)/*.c))
OBJECTS = $(SOURCES:.c=.o)

# Fuzzer-specific sources
FUZZER_SOURCES = $(filter-out $(SRCDIR)/main.c, $(wildcard $(SRCDIR)/*.c))
FUZZER_OBJECTS = $(FUZZER_SOURCES:.c=.o)

# Target executable
TARGET = rlpx_client

# Default target
all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

# Pattern rule for object files
$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean target
clean:
	rm -f $(OBJECTS) $(FUZZER_OBJECTS) $(TARGET) rlpx_fuzzer tests/test_crypto tests/test_rlp tests/test_handshake

# Show what files will be compiled
show-files:
	@echo "Source files found:"
	@ls -la $(SRCDIR)/*.c 2>/dev/null || echo "No .c files found in $(SRCDIR)/"
	@echo "Object files to create:"
	@echo $(OBJECTS)

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install -y libssl-dev libsecp256k1-dev build-essential

# Test individual file compilation
test-build:
	@echo "Testing compilation of individual files..."
	@for file in $(SOURCES); do \
		echo "Compiling $$file..."; \
		$(CC) $(CFLAGS) -c $$file -o $${file%.c}.o || exit 1; \
	done
	@echo "All files compile successfully"

# Debug build
debug: CFLAGS += -DDEBUG -g3
debug: $(TARGET)

# Fuzzer executable
fuzzer: $(FUZZER_OBJECTS)
	$(CC) $(FUZZER_OBJECTS) -o rlpx_fuzzer $(LDFLAGS)

.PHONY: all clean show-files install-deps test-build debug fuzzer test

# Unit tests
TEST_OBJECTS = $(filter-out $(SRCDIR)/main.o, $(OBJECTS))
test: $(TEST_OBJECTS)
	@for t in crypto rlp handshake; do \
		$(CC) $(CFLAGS) tests/test_$$t.c $(TEST_OBJECTS) -o tests/test_$$t $(LDFLAGS) && ./tests/test_$$t || exit 1; \
	done
