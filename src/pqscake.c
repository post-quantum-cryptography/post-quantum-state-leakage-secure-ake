#include <tomcrypt.h>
#include <oqs/sig.h>
#include <oqs/kem.h>
#include "pqscake.h"

// helpers
#define KEM_PUB_KEY_LEN(x) GLUE(OQS_KEM_,GLUE(x,_length_public_key))
#define SIG_PUB_KEY_LEN(x) GLUE(OQS_SIG_,GLUE(x,_length_public_key))
#define KEM_CT_LEN(x) GLUE(OQS_KEM_,GLUE(x,_length_ciphertext))

// Macro magic needed to initialize parameters for KEM and SIG scheme
#define REG_ALGS(sig, kem)                                      \
{                                                               \
    .alg_name = STR(GLUE(sig, GLUE(_, kem))),                   \
    .sig_id = GLUE(OQS_SIG_alg_, sig),                          \
    .kem_id = GLUE(OQS_KEM_alg_, kem),                          \
    .sig_pub_sz = GLUE(OQS_SIG_,GLUE(sig,_length_public_key)),  \
    .sig_prv_sz = GLUE(OQS_SIG_,GLUE(sig,_length_secret_key)),  \
    .sig_sz = GLUE(OQS_SIG_,GLUE(sig,_length_signature)),       \
    .kem_pub_sz = GLUE(OQS_KEM_,GLUE(kem,_length_public_key)),  \
    .kem_prv_sz = GLUE(OQS_KEM_,GLUE(kem,_length_secret_key)),  \
    .kem_ss_sz = GLUE(OQS_KEM_,GLUE(kem,_length_shared_secret)),\
    .kem_ct_sz = GLUE(OQS_KEM_,GLUE(kem,_length_ciphertext)),   \
    .sid_pfx_sz = (2*IDENT_LEN +                                \
        2*(KEM_PUB_KEY_LEN(kem) + SIG_PUB_KEY_LEN(sig))),       \
    .sid_sz = (2*IDENT_LEN +                                    \
        2*(KEM_PUB_KEY_LEN(kem) + SIG_PUB_KEY_LEN(sig)) +       \
        KEM_PUB_KEY_LEN(kem) + 2*KEM_CT_LEN(kem))               \
}

// algs array stores parameters for all the instantiations
const params_t algs[129] = {
    REG_ALGS(picnic3_L1, saber_lightsaber),
    REG_ALGS(picnic3_L1, classic_mceliece_348864f),
    REG_ALGS(picnic3_L1, sike_p434),
    REG_ALGS(picnic3_L1, ntru_hps2048509),
    REG_ALGS(picnic3_L1, kyber_512),
    REG_ALGS(picnic3_L1, frodokem_640_shake),
    REG_ALGS(picnic3_L1, hqc_128_1_cca2),
    REG_ALGS(picnic3_L1, bike1_l1_fo),
    REG_ALGS(picnic3_L1, sike_p434_compressed),
    REG_ALGS(sphincs_shake256_128f_simple, saber_lightsaber),
    REG_ALGS(sphincs_shake256_128f_simple, classic_mceliece_348864f),
    REG_ALGS(sphincs_shake256_128f_simple, sike_p434),
    REG_ALGS(sphincs_shake256_128f_simple, ntru_hps2048509),
    REG_ALGS(sphincs_shake256_128f_simple, kyber_512),
    REG_ALGS(sphincs_shake256_128f_simple, frodokem_640_shake),
    REG_ALGS(sphincs_shake256_128f_simple, hqc_128_1_cca2),
    REG_ALGS(sphincs_shake256_128f_simple, bike1_l1_fo),
    REG_ALGS(sphincs_shake256_128f_simple, sike_p434_compressed),
    REG_ALGS(rainbow_Ia_classic, saber_lightsaber),
    REG_ALGS(rainbow_Ia_classic, classic_mceliece_348864f),
    REG_ALGS(rainbow_Ia_classic, sike_p434),
    REG_ALGS(rainbow_Ia_classic, ntru_hps2048509),
    REG_ALGS(rainbow_Ia_classic, kyber_512),
    REG_ALGS(rainbow_Ia_classic, frodokem_640_shake),
    REG_ALGS(rainbow_Ia_classic, hqc_128_1_cca2),
    REG_ALGS(rainbow_Ia_classic, bike1_l1_fo),
    REG_ALGS(rainbow_Ia_classic, sike_p434_compressed),
    REG_ALGS(falcon_512, saber_lightsaber),
    REG_ALGS(falcon_512, classic_mceliece_348864f),
    REG_ALGS(falcon_512, sike_p434),
    REG_ALGS(falcon_512, ntru_hps2048509),
    REG_ALGS(falcon_512, kyber_512),
    REG_ALGS(falcon_512, frodokem_640_shake),
    REG_ALGS(falcon_512, hqc_128_1_cca2),
    REG_ALGS(falcon_512, bike1_l1_fo),
    REG_ALGS(falcon_512, sike_p434_compressed),
    REG_ALGS(dilithium_2, saber_lightsaber),
    REG_ALGS(dilithium_2, classic_mceliece_348864f),
    REG_ALGS(dilithium_2, sike_p434),
    REG_ALGS(dilithium_2, ntru_hps2048509),
    REG_ALGS(dilithium_2, kyber_512),
    REG_ALGS(dilithium_2, frodokem_640_shake),
    REG_ALGS(dilithium_2, hqc_128_1_cca2),
    REG_ALGS(dilithium_2, bike1_l1_fo),
    REG_ALGS(dilithium_2, sike_p434_compressed),
    REG_ALGS(dilithium_4, classic_mceliece_460896f),
    REG_ALGS(dilithium_4, saber_saber),
    REG_ALGS(dilithium_4, kyber_768),
    REG_ALGS(dilithium_4, ntru_hps2048677),
    REG_ALGS(dilithium_4, hqc_192_1_cca2),
    REG_ALGS(dilithium_4, sike_p610_compressed),
    REG_ALGS(dilithium_4, ntru_hrss701),
    REG_ALGS(dilithium_4, frodokem_976_shake),
    REG_ALGS(dilithium_4, bike1_l3_fo),
    REG_ALGS(dilithium_4, sike_p610),
    REG_ALGS(sphincs_shake256_192f_simple, classic_mceliece_460896f),
    REG_ALGS(sphincs_shake256_192f_simple, saber_saber),
    REG_ALGS(sphincs_shake256_192f_simple, kyber_768),
    REG_ALGS(sphincs_shake256_192f_simple, ntru_hps2048677),
    REG_ALGS(sphincs_shake256_192f_simple, hqc_192_1_cca2),
    REG_ALGS(sphincs_shake256_192f_simple, sike_p610_compressed),
    REG_ALGS(sphincs_shake256_192f_simple, ntru_hrss701),
    REG_ALGS(sphincs_shake256_192f_simple, frodokem_976_shake),
    REG_ALGS(sphincs_shake256_192f_simple, bike1_l3_fo),
    REG_ALGS(sphincs_shake256_192f_simple, sike_p610),
    REG_ALGS(picnic3_L3, classic_mceliece_460896f),
    REG_ALGS(picnic3_L3, saber_saber),
    REG_ALGS(picnic3_L3, kyber_768),
    REG_ALGS(picnic3_L3, ntru_hps2048677),
    REG_ALGS(picnic3_L3, hqc_192_1_cca2),
    REG_ALGS(picnic3_L3, sike_p610_compressed),
    REG_ALGS(picnic3_L3, ntru_hrss701),
    REG_ALGS(picnic3_L3, frodokem_976_shake),
    REG_ALGS(picnic3_L3, bike1_l3_fo),
    REG_ALGS(picnic3_L3, sike_p610),
    REG_ALGS(rainbow_IIIc_classic, classic_mceliece_460896f),
    REG_ALGS(rainbow_IIIc_classic, saber_saber),
    REG_ALGS(rainbow_IIIc_classic, kyber_768),
    REG_ALGS(rainbow_IIIc_classic, ntru_hps2048677),
    REG_ALGS(rainbow_IIIc_classic, hqc_192_1_cca2),
    REG_ALGS(rainbow_IIIc_classic, sike_p610_compressed),
    REG_ALGS(rainbow_IIIc_classic, ntru_hrss701),
    REG_ALGS(rainbow_IIIc_classic, frodokem_976_shake),
    REG_ALGS(rainbow_IIIc_classic, bike1_l3_fo),
    REG_ALGS(rainbow_IIIc_classic, sike_p610),
    REG_ALGS(picnic3_L5, sike_p751_compressed),
    REG_ALGS(picnic3_L5, saber_firesaber),
    REG_ALGS(picnic3_L5, frodokem_1344_shake),
    REG_ALGS(picnic3_L5, sike_p751),
    REG_ALGS(picnic3_L5, classic_mceliece_6960119f),
    REG_ALGS(picnic3_L5, kyber_1024),
    REG_ALGS(picnic3_L5, ntru_hps4096821),
    REG_ALGS(picnic3_L5, hqc_256_1_cca2),
    REG_ALGS(picnic3_L5, classic_mceliece_6688128f),
    REG_ALGS(picnic3_L5, hqc_256_3_cca2),
    REG_ALGS(picnic3_L5, classic_mceliece_8192128f),
    REG_ALGS(rainbow_Vc_classic, sike_p751_compressed),
    REG_ALGS(rainbow_Vc_classic, saber_firesaber),
    REG_ALGS(rainbow_Vc_classic, frodokem_1344_shake),
    REG_ALGS(rainbow_Vc_classic, sike_p751),
    REG_ALGS(rainbow_Vc_classic, classic_mceliece_6960119f),
    REG_ALGS(rainbow_Vc_classic, kyber_1024),
    REG_ALGS(rainbow_Vc_classic, ntru_hps4096821),
    REG_ALGS(rainbow_Vc_classic, hqc_256_1_cca2),
    REG_ALGS(rainbow_Vc_classic, classic_mceliece_6688128f),
    REG_ALGS(rainbow_Vc_classic, hqc_256_3_cca2),
    REG_ALGS(rainbow_Vc_classic, classic_mceliece_8192128f),
    REG_ALGS(sphincs_shake256_256f_simple, sike_p751_compressed),
    REG_ALGS(sphincs_shake256_256f_simple, saber_firesaber),
    REG_ALGS(sphincs_shake256_256f_simple, frodokem_1344_shake),
    REG_ALGS(sphincs_shake256_256f_simple, sike_p751),
    REG_ALGS(sphincs_shake256_256f_simple, classic_mceliece_6960119f),
    REG_ALGS(sphincs_shake256_256f_simple, kyber_1024),
    REG_ALGS(sphincs_shake256_256f_simple, ntru_hps4096821),
    REG_ALGS(sphincs_shake256_256f_simple, hqc_256_1_cca2),
    REG_ALGS(sphincs_shake256_256f_simple, classic_mceliece_6688128f),
    REG_ALGS(sphincs_shake256_256f_simple, hqc_256_3_cca2),
    REG_ALGS(sphincs_shake256_256f_simple, classic_mceliece_8192128f),
    REG_ALGS(falcon_1024, sike_p751_compressed),
    REG_ALGS(falcon_1024, saber_firesaber),
    REG_ALGS(falcon_1024, frodokem_1344_shake),
    REG_ALGS(falcon_1024, sike_p751),
    REG_ALGS(falcon_1024, classic_mceliece_6960119f),
    REG_ALGS(falcon_1024, kyber_1024),
    REG_ALGS(falcon_1024, ntru_hps4096821),
    REG_ALGS(falcon_1024, hqc_256_1_cca2),
    REG_ALGS(falcon_1024, classic_mceliece_6688128f),
    REG_ALGS(falcon_1024, hqc_256_3_cca2),
    REG_ALGS(falcon_1024, classic_mceliece_8192128f),
};

const size_t alg_num = ASZ(algs);
const params_t *get_alg_params(size_t i) {
    return &algs[i];
}

static const size_t get_kem_security_bytelen(const OQS_KEM *kem) {
    switch(kem->claimed_nist_level) {
        case 1: return 16;
        case 3: return 24;
        case 5: return 32;
        default:
            // this implementation doesn't support any other
            // security level
            assert(false);
    }
}

#define CHECK_OQS(exp)                                      \
do {                                                        \
    OQS_STATUS stat__ = exp;                                \
    if(stat__ != OQS_SUCCESS) {                             \
        fprintf(stderr, "ERROR[%d]: %s\n", stat__, #exp);   \
        goto err;                                           \
    }                                                       \
} while(0)

// Self test checks if all needed tools are available.
void self_test() {
    for(size_t i=0; i<alg_num; i++) {
        assert(OQS_SIG_alg_is_enabled(algs[i].sig_id));
        assert(OQS_KEM_alg_is_enabled(algs[i].kem_id));
    }
    // Ensure MAX_SIG_LEN is big enough to store
    // the longest sig size.
    for(size_t i=0; i<alg_num; i++) {
        assert(algs[i].sig_sz<=MAX_SIG_LEN);
    }
    assert(find_hash("sha256") != -1);
}

static void prf(uint8_t *out, size_t outsz,
    const uint8_t *key, size_t keysz,
    const buf_t *msg, uint8_t d) {

    int hash = find_hash("sha256");
    size_t tmp = outsz;
    hmac_state *hmac;
    int err;
    uint8_t sep[1] = {d};

    hmac = XMALLOC(sizeof(hmac_state));
    if(!hmac) abort();

    err = hmac_init(hmac, hash, key, keysz);
    err |= hmac_process(hmac, sep, 1);
    err |= hmac_process(hmac, msg->p, msg->sz);
    err |= hmac_done(hmac, out, &outsz);
    XFREE(hmac);

    assert(err == CRYPT_OK);
}

// Implementation of Ext_s. Currently it is simply a PRF
static inline void ext_s(uint8_t *out, size_t outsz,
    uint8_t seed[SEED_SZ], const buf_t *in) {
    prf(out, outsz, seed, SEED_SZ, in, 2);
}

bool init_party(struct part_t *p, uint8_t role, uint8_t alg_id) {
    bool ret = false;
    uint8_t tmp[SEED_SZ];
    OQS_KEM *kem_ctx = OQS_KEM_new(algs[alg_id].kem_id);
    OQS_SIG *sig_ctx = OQS_SIG_new(algs[alg_id].sig_id);
    buf_init(&p->kem_eph_prv_key, algs[alg_id].kem_prv_sz);
    buf_init(&p->kp.pub_key, algs[alg_id].kem_pub_sz);
    buf_init(&p->kp.prv_key, algs[alg_id].kem_prv_sz);
    buf_init(&p->kp_sig.pub_key, algs[alg_id].sig_pub_sz);
    buf_init(&p->kp_sig.prv_key, algs[alg_id].sig_prv_sz);

    // generate long term signing and kem key
    CHECK_OQS(
        OQS_SIG_keypair(sig_ctx,
            p->kp_sig.pub_key.p,
            p->kp_sig.prv_key.p));
    CHECK_OQS(
        OQS_KEM_keypair(kem_ctx,
            p->kp.pub_key.p, p->kp.prv_key.p));
    p->role = role;
    p->alg_id = alg_id;

    OQS_randombytes(tmp, ASZ(tmp));
    ext_s(p->ident, IDENT_LEN, tmp, &p->kp.prv_key);
    ret = true;

err:
    if (!ret) {
        buf_free(&p->kem_eph_prv_key);
        buf_free(&p->kp.pub_key);
        buf_free(&p->kp.prv_key);
        buf_free(&p->kp_sig.pub_key);
        buf_free(&p->kp_sig.prv_key);
    }
    OQS_SIG_free(sig_ctx);
    OQS_KEM_free(kem_ctx);
    return ret;
}

void clean_party(part_t *p) {
    buf_free(&p->kem_eph_prv_key);
    buf_free(&p->kp.pub_key);
    buf_free(&p->kp.prv_key);
    buf_free(&p->kp_sig.pub_key);
    buf_free(&p->kp_sig.prv_key);
}

void init_session(comm_ctx_t *c, part_t p[2]) {
    assert(p[0].alg_id == p[1].alg_id);

    c->params = &algs[p[0].alg_id];
    c->kem_ctx = OQS_KEM_new(c->params->kem_id);
    c->sig_ctx = OQS_SIG_new(c->params->sig_id);
    OQS_randombytes(c->seed, ASZ(c->seed));

    assert(c->kem_ctx);
    assert(c->sig_ctx);

    // Init all the memory used
    buf_init(&c->setup.init_kem_pub_key, c->params->kem_pub_sz);
    buf_init(&c->setup.resp_sig_pub_key, c->params->sig_pub_sz);
    buf_init(&c->session.pub_key_eph, c->params->kem_pub_sz);
    buf_init(&c->session.ct_st, c->params->kem_ct_sz);
    buf_init(&c->session.ct_eph, c->params->kem_ct_sz);
    buf_init(&c->session.sign, c->params->sig_sz);
    buf_init(&c->session.sid_pfx, c->params->sid_pfx_sz);
    buf_init(&c->w.sid, c->params->sid_sz);
    buf_init(&c->w.ss_st, c->params->kem_ss_sz);
    buf_init(&c->w.ss_eph, c->params->kem_ss_sz);

    // Calculate session ID prefix: P_i||P_j||lpk_i||lpk_j
    uint8_t *psid = c->session.sid_pfx.p;
    memcpy(psid, p[0].ident, ASZ(p[0].ident));
    psid += ASZ(p[0].ident);
    memcpy(psid, p[1].ident, ASZ(p[1].ident));
    psid += ASZ(p[1].ident);

    // lpk_i
    copy_from_buf(psid, p[0].kp.pub_key.sz, &p[0].kp.pub_key);
    psid += p[0].kp.pub_key.sz;

    copy_from_buf(psid, p[0].kp_sig.pub_key.sz, &p[0].kp_sig.pub_key);
    psid += p[0].kp_sig.pub_key.sz;

    // lpk_j
    copy_from_buf(psid, p[1].kp.pub_key.sz, &p[1].kp.pub_key);
    psid += p[1].kp.pub_key.sz;
    copy_from_buf(psid, p[1].kp_sig.pub_key.sz, &p[1].kp_sig.pub_key);
}

static void get_session_key(
    uint8_t key[MAX_KJKH_LEN],
    uint8_t seed[SEED_SZ],
    buf_t *sid, buf_t *ss_st, buf_t *ss_eph,
    size_t sec_sz, size_t sig_sz) {

    const size_t outsz = sec_sz+sig_sz;
    uint8_t key1[MAX_SEC_BYTE_LEN], key2[MAX_SEC_BYTE_LEN];
    uint8_t out1[MAX_KJKH_LEN]={0}, out2[MAX_KJKH_LEN]={0};

    // Compute K_1 and K_2 of size sec_sz
    ext_s(key1, sec_sz, seed, ss_st);
    ext_s(key2, sec_sz, seed, ss_eph);

    // PRF_k1(sid) XOR PRF_k2(sid)
    prf(out1, outsz, key1, sec_sz, sid, 1);
    prf(out2, outsz, key2, sec_sz, sid, 1);
    for(size_t i=0; i<outsz; i++) {
        key[i] = out1[i] ^ out2[i];
    }
}

void init_lib() {
    // init libtomcrypt
    register_all_ciphers();
    register_all_hashes();
    register_all_prngs();
    self_test();
}

static void finish_sid(buf_t *sid, const comm_ctx_t *c) {
    uint8_t *psid = sid->p;
    copy_from_buf(psid, c->session.sid_pfx.sz, &c->session.sid_pfx);
    psid += c->params->sid_pfx_sz;

    // ek_t
    copy_from_buf(psid, c->session.pub_key_eph.sz, &c->session.pub_key_eph);
    psid += c->session.pub_key_eph.sz;

    // ct
    copy_from_buf(psid, c->session.ct_st.sz, &c->session.ct_st);
    psid += c->session.ct_st.sz;

    // ct_eph
    copy_from_buf(psid, c->session.ct_eph.sz, &c->session.ct_eph);
}

bool offer(comm_ctx_t *c, /*const*/part_t *p) {
    // store ephemeral KEM public key in session and keep private key local
    CHECK_OQS(
        OQS_KEM_keypair(c->kem_ctx,
            c->session.pub_key_eph.p,
            p->kem_eph_prv_key.p));
    return !!copy_buf(&c->setup.init_kem_pub_key, &p->kp.pub_key);;
err:
    return false;
}

bool accept(uint8_t *session_key, comm_ctx_t *c, const part_t *p) {
    buf_t *ss_st = &c->w.ss_st;
    buf_t *ss_eph = &c->w.ss_eph;
    buf_t *sid = &c->w.sid;
    uint8_t concat_sess_key[MAX_KJKH_LEN] = {0};

    CHECK_OQS(
        OQS_KEM_encaps(c->kem_ctx,
            c->session.ct_st.p, ss_st->p,
            c->setup.init_kem_pub_key.p));

    CHECK_OQS(
        OQS_KEM_encaps(c->kem_ctx,
            c->session.ct_eph.p, ss_eph->p,
            c->session.pub_key_eph.p));

    finish_sid(sid, c);

    CHECK_OQS(
        OQS_SIG_sign(c->sig_ctx,
            c->session.sign.p, &c->session.sign.sz,
            sid->p, sid->sz,
            p->kp_sig.prv_key.p));

    const size_t sec_len = get_kem_security_bytelen(c->kem_ctx);
    get_session_key(concat_sess_key, c->seed, sid, ss_st, ss_eph, sec_len,
        c->session.sign.sz);

    // sigma = c XOR kh
    for (size_t i=0; i<c->session.sign.sz; i++) {
        c->session.sign.p[i] ^= concat_sess_key[sec_len+i];
    }
    copy_buf(&c->setup.resp_sig_pub_key, &p->kp_sig.pub_key);

    // copy-out k_j
    memcpy(session_key, concat_sess_key, sec_len);
    return true;
err:
    return false;
}

bool finalize(uint8_t *session_key, comm_ctx_t *c, const part_t *p) {
    buf_t *sid = &c->w.sid;
    buf_t *ss_st = &c->w.ss_st;
    buf_t *ss_eph = &c->w.ss_eph;
    uint8_t concat_sess_key[MAX_KJKH_LEN] = {0};

    finish_sid(sid, c);
    CHECK_OQS(
        OQS_KEM_decaps(c->kem_ctx,
            ss_st->p,
            c->session.ct_st.p,
            p->kp.prv_key.p));

    CHECK_OQS(
        OQS_KEM_decaps(c->kem_ctx,
            ss_eph->p,
            c->session.ct_eph.p,
            p->kem_eph_prv_key.p));


    const size_t sec_len = get_kem_security_bytelen(c->kem_ctx);
    get_session_key(concat_sess_key, c->seed, sid, ss_st, ss_eph, sec_len,
        c->session.sign.sz);

    // sigma = c XOR kh
    for (size_t i=0; i<c->session.sign.sz; i++) {
        c->session.sign.p[i] ^= concat_sess_key[sec_len+i];
    }

    CHECK_OQS(
        OQS_SIG_verify(c->sig_ctx,
            sid->p, sid->sz,
            c->session.sign.p, c->session.sign.sz,
            c->setup.resp_sig_pub_key.p));

    // copy-out k_i
    memcpy(session_key, concat_sess_key, sec_len);

    return true;
err:
    return false;
}

void clean_session(comm_ctx_t *c) {
    buf_free(&c->setup.init_kem_pub_key);
    buf_free(&c->setup.resp_sig_pub_key);
    buf_free(&c->session.pub_key_eph);
    buf_free(&c->session.ct_st);
    buf_free(&c->session.ct_eph);
    buf_free(&c->session.sign);
    buf_free(&c->session.sid_pfx);
    buf_free(&c->w.sid);
    buf_free(&c->w.ss_st);
    buf_free(&c->w.ss_eph);

    OQS_SIG_free(c->sig_ctx);
    OQS_KEM_free(c->kem_ctx);
}

size_t get_received_init_data_len(const comm_ctx_t *c) {
    return (2*c->params->kem_pub_sz) + c->params->sig_pub_sz;
}

size_t get_session_sent_data_len(const comm_ctx_t *c) {
    return c->session.pub_key_eph.sz;
}

size_t get_session_received_data_len(const comm_ctx_t *c) {
    return c->session.ct_st.sz +
            c->session.ct_eph.sz +
            c->session.sign.sz;
}

size_t get_scheme_sec(const comm_ctx_t *c) {
    return c->kem_ctx->claimed_nist_level;
}
