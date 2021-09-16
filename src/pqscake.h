#ifndef LIB_H_
#define LIB_H_

#include <stdint.h>
#include <stddef.h>
#include <pqc/pqc.h>
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SEED_SZ 32U
#define IDENT_LEN 16

// Parameters of the KEM and signature scheme
typedef struct params_t {
	const char* alg_name;
	const uint8_t sig_id;
	const uint8_t kem_id;

	size_t sig_pub_sz;
	size_t sig_prv_sz;
	size_t sig_sz;

	size_t kem_pub_sz;
	size_t kem_prv_sz;
	size_t kem_ss_sz;
	size_t kem_ct_sz;

	size_t sid_pfx_sz;
	size_t sid_sz;

	uint8_t nist_level;
} params_t;

// Kem keypair
typedef struct kem_keypair_t {
	buf_t pub_key;
	buf_t prv_key;
} kem_keypair_t;

// Signature keypair
typedef struct sig_keypair_t {
	buf_t pub_key;
	buf_t prv_key;
} sig_keypair_t;

// defines a party in the protocol
enum {kInit, kResp};
typedef struct part_t {
	uint8_t alg_id;
	uint8_t role;

	uint8_t ident[IDENT_LEN];
	struct sig_keypair_t kp_sig;
	struct kem_keypair_t kp;
	buf_t kem_eph_prv_key;
} part_t;

// Defines buffers of variable size, which can't be
// allocated on the stack.
typedef struct workspace_t {
	buf_t sid;
	buf_t ss_st;
	buf_t ss_eph;
} workspace_t;

// Communication context
typedef struct comm_ctx_t {
	const params_t *params;
	const pqc_ctx_t *sig_ctx;
	const pqc_ctx_t *kem_ctx;
	uint8_t seed[SEED_SZ];

	struct {
		buf_t init_kem_pub_key;
		buf_t init_sig_pub_key;
		buf_t resp_sig_pub_key;
	} setup;

	struct {
		// sender
		buf_t pub_key_eph;
		buf_t sign_A;	// Sigma A
		// recipient
		buf_t ct_st;    // KEM ciphertext
		buf_t ct_eph;   // wKEM ciphertext
		buf_t sign;     // sign XOR k-hat
		buf_t sid_pfx;  // prefix of a SID (P_i||P_j||lpk_i||lpk_j)
	} session;
	// emulates stack on heap
	workspace_t w;
} comm_ctx_t;

// Initialize lib
void init_lib();
// Initiator offers it's ephemeral key share
bool offer(comm_ctx_t *c, /*const*/part_t *p);
// Responder accept the offer and generates it's part of the key share
bool accept(uint8_t *session_key, comm_ctx_t *c, const part_t *p);
// Initiator finalizes session key calculations
bool finalize(uint8_t *session_key, comm_ctx_t *c, const part_t *p);
// Initializes state of the communication party
bool init_party(struct part_t *p, uint8_t role, uint8_t alg_id);
// Initializes the session
void init_session(comm_ctx_t *c, part_t p[2]);
// Cleans the session
void clean_session(comm_ctx_t *c);
// Frees memory used by the party
void clean_party(part_t *p);
// Get session parameters for the algorithm i as defined in algs[] array
const params_t *get_alg_params(size_t i);
// Amount of bytes exchanged during initialization phase (long term signing and KEM key)
size_t get_received_init_data_len(const comm_ctx_t *c);
// Amount of bytes sent by initiator (received by reciver)
size_t get_session_sent_data_len(const comm_ctx_t *c);
// Amount of bytes received by initiator (sent by reciver)
size_t get_session_received_data_len(const comm_ctx_t *c);
// Claimed security level as defined by NIST
size_t get_scheme_sec(const comm_ctx_t *c);
#ifdef __cplusplus
}
#endif

#endif
