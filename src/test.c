#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include "pqscake.h"
#include "utils.h"

extern const size_t alg_num;

bool roundtrip(uint8_t alg_id) {
	part_t parts[2];
	comm_ctx_t session = {0};
	uint8_t session_key_resp[MAX_SEC_BYTE_LEN] = {0},
			session_key_init[MAX_SEC_BYTE_LEN] = {0},
			zeros[MAX_SEC_BYTE_LEN] = {0};

	// init all parties
	if (!init_party(&parts[0], kInit, alg_id) ||
		!init_party(&parts[1], kResp, alg_id)) {
		return false;
	}
	init_session(&session, parts);

	if (!offer(&session, &parts[0]) ||
		!accept(session_key_resp, &session, &parts[1]) ||
		!finalize(session_key_init, &session, &parts[0])) {
		return false;
	}

	if (!memcmp(zeros, session_key_init, ASZ(session_key_init))) {
		printf("ALG[%u] failed. Zero buffer returned\n", alg_id);
		return false;
	}

	if (memcmp(session_key_resp, session_key_init, ASZ(session_key_init))) {
		printf("ALG[%u] failed\n", alg_id);
		return false;
	}

	clean_session(&session);
	clean_party(&parts[0]);
	clean_party(&parts[1]);
	return true;
}

int main() {
	init_lib();
	for (size_t i=0; i<alg_num; i++) {
		printf("Running test for %s\n", get_alg_params(i)->alg_name);
		if (!roundtrip(i)) {
			printf("Failed\n");
		}
	}
	return 0;
}
