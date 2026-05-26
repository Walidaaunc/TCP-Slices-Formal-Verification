//
// Created by Walid Ait Amrou on 3/21/26.
//

// The off-path attacker is assumed to have already identified the correct IP
// and port number for the victim's connection (e.g., via a previous
// port-probing side channel). The goal of this specific verification
// is to see if the attacker can now infer the sensitive TCP sequence number.

#include <assert.h>
#include <stdint.h>

#define NO_RESPONSE 0
#define ESTABLISHED 1
#define CHALLENGE_ACK 2

#define SEQ_MIN_NUMBER 0
#define SEQ_MAX_NUMBER UINT32_MAX // The standard TCP sequence number space is 2^32	unique sequence numbers
#define MAX_WINDOW_SIZE UINT16_MAX	// The maximum standard TCP window size is 2^16 (65,535) bytes

// Maximum number of CHALLENGE_ACK responses allowed locally before the rate limiter blocks further ACK generation.
#define MAX_CHALLENGE_ACKS 3

#ifndef K_BOUND
#define K_BOUND 3 // Default value if not provided via -DK_BOUND=...
#endif

// Declares nondeterministic helpers for CBMC
int nondet_int();  // Allows exploration of all possible integer values under the given constraints
_Bool nondet_bool();

typedef struct {
    int state;
    // Casting to uint32_t ensures values wrap around naturally without overflow
    uint32_t seq;   // Secret for victim
    int challenge_ack_count; // Private rate limiter for this connection
} tcp_conn;

// This function describes how the server handles an incoming packet
int process_packet(tcp_conn *conn, int incoming_seq) {
    if (conn->state == ESTABLISHED) {
		// If the incoming_seq matches the connection's secret sequence number (whether from the
		// legitimate peer or an attacker), the packet is accepted and treated as valid established traffic
        if (incoming_seq == conn->seq) {
			return ESTABLISHED;
        }

        uint32_t difference = incoming_seq - conn->seq;

		// If the sequence number falls within the TCP receive window but does not match the expected
		// sequence number, the packet is considered suspicious and triggers a Challenge ACK response,
		// as implemented in real TCP stacks for in-window but unexpected segments
		if (difference < MAX_WINDOW_SIZE || difference > (UINT32_MAX - MAX_WINDOW_SIZE)) {
			// Importantly, the ACK is only sent if the per-connection limit has not been exceeded
		    if (conn->challenge_ack_count < MAX_CHALLENGE_ACKS) {
                // When an ACK is sent, the function increments the per-connection counter
		        conn->challenge_ack_count++;
                return CHALLENGE_ACK;
            }
		}
    }

	// Default behavior: silently drops or ignores the packet
    return NO_RESPONSE;
}

// Simulates an interleaving of events between a victim and an attacker.
// The schedule[] array controls each step: true means the victim processes a normal packet,
// while false means the attacker sends a probe.
int run_trace(int secret_seq, int attacker_seq_guess, int attacker_own_seq, _Bool schedule[]) {
    tcp_conn victim = { .state = ESTABLISHED, .seq = secret_seq, .challenge_ack_count = 0 };
    int side_channel_obs = NO_RESPONSE;

    // Attacker's own legitimate connection where they know the sequence number
    tcp_conn attacker_own_conn = { .state = ESTABLISHED, .seq = attacker_own_seq, .challenge_ack_count = 0 };

    for (int i = 0; i < K_BOUND; i++) {
        if (schedule[i]) {
            // Victim processes a packet using its legitimate sequence number
            process_packet(&victim, victim.seq);
        } else {
            // Attacker blindly sends a probe with the guessed sequence number
            process_packet(&victim, attacker_seq_guess);

            // Immediately after, the attacker issues a probe on their own established connection by
			// processing an in-window packet that does not match the expected sequence number (in attempt to
			// trigger the Challenge ACK path).
            uint32_t probe_seq = attacker_own_conn.seq + (uint32_t) (MAX_WINDOW_SIZE - 1);
            side_channel_obs = process_packet(&attacker_own_conn, probe_seq);
        }
    }

    // Returns the last observable response seen by the attacker
    return side_channel_obs; // The attacker only sees if their own probe was blocked
}

int main() {
    // High security secret inputs
    int secret_seq_num_1 = nondet_int();
    int secret_seq_num_2 = nondet_int();

    __CPROVER_assume(secret_seq_num_1 >= SEQ_MIN_NUMBER && secret_seq_num_1 <= SEQ_MAX_NUMBER);
    __CPROVER_assume(secret_seq_num_2 >= SEQ_MIN_NUMBER && secret_seq_num_2 <= SEQ_MAX_NUMBER);
    __CPROVER_assume(secret_seq_num_1 != secret_seq_num_2);  // The two secrets are assumed to be distinct

    // Low security attacker inputs
    int attacker_seq_num_guess = nondet_int();
    __CPROVER_assume(attacker_seq_num_guess >= SEQ_MIN_NUMBER && attacker_seq_num_guess <= SEQ_MAX_NUMBER);
    int attacker_own_seq_num = nondet_int(); // Attacker's own sequence number
    __CPROVER_assume(attacker_own_seq_num >= SEQ_MIN_NUMBER && attacker_own_seq_num <= SEQ_MAX_NUMBER);

    // Shared schedule (same across both executions)
    _Bool schedule[K_BOUND];
    for (int i = 0; i < K_BOUND; i++) {
        schedule[i] = nondet_bool();
    }

    // The trace is executed twice using self-composition: once with the victim
    // holding secret_seq_num_1, and once with the victim holding secret_seq_num_2
    int attacker_observation_1 = run_trace(secret_seq_num_1, attacker_seq_num_guess, attacker_own_seq_num, schedule);
    int attacker_observation_2 = run_trace(secret_seq_num_2, attacker_seq_num_guess, attacker_own_seq_num, schedule);

    assert(attacker_observation_1 == attacker_observation_2);   // Non-interference property

    return 0;
}