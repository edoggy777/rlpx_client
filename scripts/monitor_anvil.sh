#!/bin/bash
# Monitor Anvil during fuzzing for crashes, errors, etc.

ANVIL_LOG="anvil_fuzz.log"
FUZZ_LOG="fuzzing_results.log"

echo "Starting Anvil monitoring..."
echo "Anvil log: $ANVIL_LOG"
echo "Fuzz results: $FUZZ_LOG"

# Start anvil with logging
anvil --fork-url "$ETH_RPC_URL" \
      --fork-block-number 18500000 \
      --no-mining \
      --host 0.0.0.0 \
      --accounts 10 \
      --balance 1000000 \
      --node-key-file anvil_privkey.bin \
      --verbose > "$ANVIL_LOG" 2>&1 &

ANVIL_PID=$!
echo "Anvil started with PID: $ANVIL_PID"

# Monitor for crashes
monitor_anvil() {
    while kill -0 $ANVIL_PID 2>/dev/null; do
        sleep 5
        
        # Check for error patterns in log
        if tail -n 100 "$ANVIL_LOG" | grep -i "panic\|error\|failed\|crash" > /dev/null; then
            echo "$(date): Potential issue detected in Anvil" >> "$FUZZ_LOG"
            tail -n 20 "$ANVIL_LOG" >> "$FUZZ_LOG"
        fi
    done
    
    echo "$(date): Anvil process terminated" >> "$FUZZ_LOG"
}

# Start monitoring in background
monitor_anvil &
MONITOR_PID=$!

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    kill $ANVIL_PID 2>/dev/null
    kill $MONITOR_PID 2>/dev/null
    wait
}

trap cleanup EXIT

echo "Monitoring started. Press Ctrl+C to stop."
echo "Run your fuzzer now..."

# Wait for user interrupt
wait $ANVIL_PID
