#include "rlpx_handshake.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

// Anvil connection parameters
#define ANVIL_HOST "127.0.0.1"
#define ANVIL_PORT 30303
#define MAX_FUZZ_ITERATIONS 1000

static volatile int running = 1;

void signal_handler(int sig) {
    running = 0;
    printf("\nFuzzing interrupted by signal %d\n", sig);
}

typedef struct {
    uint8_t* data;
    size_t len;
    const char* description;
} fuzz_test_case_t;

// Pre-defined malformed payloads for structured fuzzing
fuzz_test_case_t fuzz_cases[] = {
    // Invalid frame lengths
    {(uint8_t[]){0xFF, 0xFF, 0xFF, 0x42}, 4, "Invalid frame length"},
    {(uint8_t[]){0x00, 0x00, 0x00}, 3, "Zero length frame"},
    {(uint8_t[]){0x7F, 0xFF, 0xFF}, 3, "Maximum length frame header"},
    
    // Malformed RLP payloads
    {(uint8_t[]){0xFF, 0xFE, 0xFD, 0xFC}, 4, "Invalid RLP bytes"},
    {(uint8_t[]){0xC0}, 1, "Empty RLP list"},
    {(uint8_t[]){0xF8, 0x80}, 2, "Long form zero length"},
    
    // Protocol-level attacks
    {(uint8_t[]){0x00, 0x00, 0x10, 0x00, 0x02, 0xFF, 0xFF}, 7, "Hello with malformed capability"},
    {(uint8_t[]){0x00, 0x00, 0x04, 0x01, 0xFF, 0xFF, 0xFF}, 7, "Disconnect with invalid reason"},
    
    // Oversized payloads
    {NULL, 65536, "Maximum size payload"}, // Will be allocated
    {NULL, 1048576, "Oversized payload"}, // Will be allocated if possible
};

int connect_to_anvil(rlpx_conn_t* conn) {
    printf("Connecting to Anvil at %s:%d...\n", ANVIL_HOST, ANVIL_PORT);
    
    if (rlpx_connect(conn, ANVIL_HOST, ANVIL_PORT, "anvil_pubkey.bin") != 0) {
        fprintf(stderr, "Failed to connect to Anvil\n");
        return -1;
    }
    
    printf("✓ Connected to Anvil successfully\n");
    return 0;
}

void run_structured_fuzzing(rlpx_conn_t* conn) {
    printf("\n=== Running Structured Fuzzing Tests ===\n");
    
    size_t num_cases = sizeof(fuzz_cases) / sizeof(fuzz_cases[0]);
    
    for (size_t i = 0; i < num_cases && running; i++) {
        fuzz_test_case_t* test = &fuzz_cases[i];
        
        printf("Test %zu: %s\n", i + 1, test->description);
        
        uint8_t* payload = test->data;
        size_t len = test->len;
        
        // Allocate oversized payloads
        if (!payload && len > 0) {
            payload = malloc(len);
            if (!payload) {
                printf("  Skipped (allocation failed)\n");
                continue;
            }
            // Fill with pattern
            for (size_t j = 0; j < len; j++) {
                payload[j] = (uint8_t)(j ^ 0xAA);
            }
        }
        
        // Send the malformed data
        if (rlpx_send_frame(conn, payload, len) == 0) {
            printf("  ✓ Sent %zu bytes\n", len);
            
            // Try to receive response (may fail)
            uint8_t response[1024];
            size_t resp_len = sizeof(response);
            
            if (rlpx_recv_frame(conn, response, &resp_len) == 0) {
                printf("  ✓ Received %zu byte response\n", resp_len);
            } else {
                printf("  ⚠ No response (connection may be closed)\n");
                // Connection might be dead, attempt reconnect
                rlpx_close(conn);
                if (connect_to_anvil(conn) != 0) {
                    printf("  ✗ Reconnection failed, ending test\n");
                    break;
                }
            }
        } else {
            printf("  ✗ Send failed\n");
        }
        
        // Cleanup allocated payload
        if (payload != test->data) {
            free(payload);
        }
        
        // Brief delay between tests
        usleep(100000); // 100ms
    }
}

void run_random_fuzzing(rlpx_conn_t* conn, int iterations) {
    printf("\n=== Running Random Fuzzing (%d iterations) ===\n", iterations);
    
    srand(time(NULL));
    
    for (int i = 0; i < iterations && running; i++) {
        // Generate random payload
        size_t payload_len = 1 + (rand() % 1024); // 1-1024 bytes
        uint8_t* payload = malloc(payload_len);
        
        if (!payload) continue;
        
        // Fill with random data
        for (size_t j = 0; j < payload_len; j++) {
            payload[j] = rand() & 0xFF;
        }
        
        printf("Iteration %d: Sending %zu random bytes\n", i + 1, payload_len);
        
        // Send random frame
        int result = rlpx_send_frame(conn, payload, payload_len);
        
        if (result == 0) {
            // Try to receive (with short timeout)
            uint8_t response[1024];
            size_t resp_len = sizeof(response);
            rlpx_recv_frame(conn, response, &resp_len); // Ignore result
        } else {
            // Connection lost, try to reconnect
            printf("  Connection lost, attempting reconnect...\n");
            rlpx_close(conn);
            if (connect_to_anvil(conn) != 0) {
                printf("Reconnection failed, ending fuzzing\n");
                free(payload);
                break;
            }
        }
        
        free(payload);
        
        // Progress indicator
        if ((i + 1) % 100 == 0) {
            printf("  Progress: %d/%d iterations completed\n", i + 1, iterations);
        }
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("Anvil RLPx Fuzzer\n");
    printf("==================\n");
    
    // Initialize connection
    rlpx_conn_t conn;
    if (rlpx_init(&conn, "test_privkey.bin") != 0) {
        fprintf(stderr, "Failed to initialize RLPx client\n");
        return 1;
    }
    
    // Connect to Anvil
    if (connect_to_anvil(&conn) != 0) {
        return 1;
    }
    
    // Run fuzzing campaigns
    run_structured_fuzzing(&conn);
    
    if (running) {
        int iterations = (argc > 1) ? atoi(argv[1]) : 500;
        run_random_fuzzing(&conn, iterations);
    }
    
    rlpx_close(&conn);
    printf("\nFuzzing completed!\n");
    return 0;
}
