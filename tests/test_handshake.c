#include "../src/rlpx_handshake.h"
#include <stdio.h>
#include <assert.h>

void test_handshake_init() {
    rlpx_conn_t conn;
    assert(rlpx_init(&conn, "test_key.bin") == 0);
    assert(conn.state == RLPX_STATE_INIT);
    assert(conn.sockfd == -1);
    
    printf("✓ Handshake initialization test passed\n");
}

void test_key_derivation() {
    rlpx_conn_t conn;
    rlpx_init(&conn, "test_key.bin");
    
    // Set up test data
    memset(conn.ephemeral_privkey, 0x01, 32);
    memset(conn.peer_ephemeral_pubkey, 0x04, 1);
    memset(conn.peer_ephemeral_pubkey + 1, 0x02, 64);
    
    rlpx_derive_secrets(&conn);
    
    // Check that secrets were derived (non-zero)
    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (conn.secrets.aes_secret[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    assert(!all_zero);
    
    printf("✓ Key derivation test passed\n");
}

int main() {
    test_handshake_init();
    test_key_derivation();
    printf("All handshake tests passed!\n");
    return 0;
}
