CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
INCLUDES = -Isrc/ -I/usr/local/include
LIBS = -L/usr/local/lib -lsecp256k1 -lssl -lcrypto

# Source files
SRCDIR = src
TESTDIR = tests
FUZZDIR = fuzz

SOURCES = $(SRCDIR)/net.c $(SRCDIR)/crypto_ec.c $(SRCDIR)/keccak.c \
          $(SRCDIR)/aes_mac.c $(SRCDIR)/rlp.c $(SRCDIR)/rlpx_handshake.c \
          $(SRCDIR)/rlpx_frame.c $(SRCDIR)/ecies.c

OBJECTS = $(SOURCES:.c=.o)

# Main targets
TARGET = rlpx_client
TEST_TARGETS = test_crypto test_rlp test_handshake
FUZZ_TARGET = fuzz_harness
ANVIL_FUZZER = anvil_fuzzer

.PHONY: all clean tests fuzz install anvil-setup fuzz-anvil run-anvil

all: $(TARGET)

$(TARGET): $(OBJECTS) $(SRCDIR)/main.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Object files
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

# Tests
tests: $(TEST_TARGETS)

test_crypto: $(OBJECTS) $(TESTDIR)/test_crypto.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)

test_rlp: $(OBJECTS) $(TESTDIR)/test_rlp.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)

test_handshake: $(OBJECTS) $(TESTDIR)/test_handshake.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)

# Standard fuzzing
fuzz: CFLAGS += -fsanitize=address,fuzzer -DLIBFUZZER
fuzz: $(FUZZ_TARGET)

$(FUZZ_TARGET): $(OBJECTS) $(FUZZDIR)/fuzz_harness.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)

# AFL fuzzing variant
fuzz-afl: CC = afl-gcc
fuzz-afl: CFLAGS += -DAFL_FUZZING
fuzz-afl: $(OBJECTS) $(FUZZDIR)/fuzz_harness.o
	$(CC) $(CFLAGS) $(INCLUDES) -o fuzz_harness_afl $^ $(LIBS)

# Anvil fuzzing targets
anvil-fuzzer: $(OBJECTS) $(SRCDIR)/anvil_fuzzer.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)

setup-anvil:
	@echo "Setting up Anvil keys..."
	@if [ ! -f anvil_privkey.bin ]; then \
		openssl ecparam -genkey -name secp256k1 -noout > anvil_temp.pem; \
		openssl ec -in anvil_temp.pem -text -noout | grep -A 3 "priv:" | tail -n 3 | tr -d ' :\n' | xxd -r -p > anvil_privkey.bin; \
		openssl ec -in anvil_temp.pem -pubout -outform DER | tail -c 65 > anvil_pubkey.bin; \
		rm anvil_temp.pem; \
		echo "✓ Generated anvil_privkey.bin and anvil_pubkey.bin"; \
	else \
		echo "✓ Anvil keys already exist"; \
	fi

run-anvil: setup-anvil
	@echo "Starting Anvil forked node for fuzzing..."
	@if [ -z "$(ETH_RPC_URL)" ]; then \
		echo "Warning: ETH_RPC_URL not set. Using Alchemy default."; \
		echo "Set it with: export ETH_RPC_URL=https://eth-mainnet.alchemyapi.io/client"; \
		anvil --fork-url https://eth-mainnet.alchemyapi.io/client \
		      --fork-block-number 18500000 \
		      --no-mining \
		      --host 0.0.0.0 \
		      --accounts 10 \
		      --balance 1000000; \
	else \
		anvil --fork-url $(ETH_RPC_URL) \
		      --fork-block-number 18500000 \
		      --no-mining \
		      --host 0.0.0.0 \
		      --accounts 10 \
		      --balance 1000000; \
	fi

fuzz-anvil: setup-anvil anvil-fuzzer
	@echo "Anvil Fuzzing Setup Complete!"
	@echo "================================"
	@echo "1. In terminal 1, run: make run-anvil"
	@echo "2. In terminal 2, run: ./anvil_fuzzer [iterations]"
	@echo ""
	@echo "Environment variables:"
	@echo "  ETH_RPC_URL - Your Ethereum RPC endpoint"
	@echo ""
	@echo "Files created:"
	@echo "  anvil_privkey.bin - Anvil's private key"
	@echo "  anvil_pubkey.bin  - Anvil's public key (for client)"

# Test execution
check: tests
	@echo "Running unit tests..."
	./test_crypto
	./test_rlp
	./test_handshake
	@echo "All tests passed!"

# Key generation for testing
gen-keys:
	@echo "Generating test keys..."
	openssl ecparam -genkey -name secp256k1 -noout -out test_privkey.pem
	openssl ec -in test_privkey.pem -text -noout | grep -A 3 "priv:" | tail -n 3 | tr -d ' :\n' | xxd -r -p > test_privkey.bin
	openssl ec -in test_privkey.pem -pubout -outform DER | tail -c 65 > test_pubkey.bin
	rm test_privkey.pem
	@echo "Generated test_privkey.bin and test_pubkey.bin"

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(SRCDIR)/main.o $(SRCDIR)/anvil_fuzzer.o
	rm -f $(TESTDIR)/*.o $(FUZZDIR)/*.o
	rm -f $(TARGET) $(TEST_TARGETS) $(FUZZ_TARGET) $(ANVIL_FUZZER) fuzz_harness_afl
	rm -f test_*.bin *.pem anvil_*.bin

# Deep clean (including generated keys)
distclean: clean
	rm -f anvil_privkey.bin anvil_pubkey.bin
	rm -f *.log

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt update
	sudo apt install -y libsecp256k1-dev libssl-dev build-essential xxd
	@echo "Dependencies installed"

# Install Foundry (for Anvil)
install-foundry:
	@echo "Installing Foundry (includes Anvil)..."
	curl -L https://foundry.paradigm.xyz | bash
	@echo "Run 'foundryup' to complete installation"

# Development helpers
format:
	find src/ tests/ fuzz/ -name "*.c" -o -name "*.h" | xargs clang-format -i

lint:
	find src/ tests/ fuzz/ -name "*.c" -o -name "*.h" | xargs cppcheck --enable=all

# Build variants
debug: CFLAGS += -DDEBUG -O0
debug: $(TARGET)

release: CFLAGS += -DNDEBUG -O3 -s
release: $(TARGET)

# Sanitizer builds
asan: CFLAGS += -fsanitize=address -g
asan: $(TARGET)

msan: CFLAGS += -fsanitize=memory -g
msan: $(TARGET)

# Quick test run
quick-test: $(TARGET) gen-keys
	@echo "Running quick connection test..."
	@echo "Note: This will fail without a running node, but tests the build"
	./$(TARGET) -k test_privkey.bin -P test_pubkey.bin || echo "Expected failure - no node running"

# Help target
help:
	@echo "RLPx Client Makefile"
	@echo "===================="
	@echo ""
	@echo "Build targets:"
	@echo "  all          - Build main client"
	@echo "  debug        - Build with debug symbols"
	@echo "  release      - Build optimized release"
	@echo "  asan         - Build with AddressSanitizer"
	@echo "  msan         - Build with MemorySanitizer"
	@echo ""
	@echo "Test targets:"
	@echo "  tests        - Build all unit tests"
	@echo "  check        - Run unit tests"
	@echo "  quick-test   - Quick build + connection test"
	@echo ""
	@echo "Fuzzing targets:"
	@echo "  fuzz         - Build libFuzzer target"
	@echo "  fuzz-afl     - Build AFL fuzzer target"
	@echo "  anvil-fuzzer - Build Anvil-specific fuzzer"
	@echo ""
	@echo "Anvil workflow:"
	@echo "  setup-anvil  - Generate Anvil keys"
	@echo "  run-anvil    - Start Anvil forked node"
	@echo "  fuzz-anvil   - Complete Anvil setup instructions"
	@echo ""
	@echo "Utilities:"
	@echo "  gen-keys     - Generate test keys"
	@echo "  clean        - Clean build artifacts"
	@echo "  distclean    - Clean everything including keys"
	@echo "  install-deps - Install system dependencies"
	@echo "  install-foundry - Install Foundry/Anvil"
	@echo "  format       - Format source code"
	@echo "  lint         - Run static analysis"
	@echo ""
	@echo "Example workflow:"
	@echo "  make install-deps && make install-foundry"
	@echo "  make fuzz-anvil    # Setup Anvil fuzzing"
	@echo "  make run-anvil     # Terminal 1"
	@echo "  ./anvil_fuzzer     # Terminal 2"
