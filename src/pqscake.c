#include <tomcrypt.h>
#include <pqc/pqc.h>
#include <openssl/rand.h>
#include "pqscake.h"

// Macro magic needed to initialize parameters for KEM and SIG scheme
#define REG_ALG(sig, kem, lvl)                  \
{                                               \
    .alg_name = STR(GLUE(sig, GLUE(_, kem))),   \
    .sig_id = GLUE(PQC_ALG_SIG_,sig),           \
    .kem_id = GLUE(PQC_ALG_KEM_,kem),           \
    .nist_level = lvl                           \
}

static void register_algo(params_t *algs,
    const pqc_ctx_t *sig_alg, const pqc_ctx_t *kem_alg) {
    algs->sig_pub_sz = pqc_public_key_bsz(sig_alg);
    algs->sig_prv_sz = pqc_private_key_bsz(sig_alg);
    algs->sig_sz = pqc_signature_bsz(sig_alg);
    algs->kem_pub_sz = pqc_public_key_bsz(kem_alg);
    algs->kem_prv_sz = pqc_private_key_bsz(kem_alg);
    algs->kem_ss_sz = pqc_shared_secret_bsz(kem_alg);
    algs->kem_ct_sz = pqc_ciphertext_bsz(kem_alg);
    algs->sid_pfx_sz = 2*IDENT_LEN +
        2*(pqc_public_key_bsz(kem_alg)+pqc_public_key_bsz(sig_alg));
    algs->sid_sz = 2*IDENT_LEN +
        2*(pqc_public_key_bsz(kem_alg) + pqc_public_key_bsz(sig_alg)) +
        pqc_public_key_bsz(kem_alg) + 2*pqc_ciphertext_bsz(kem_alg);
}

static const size_t get_kem_security_bytelen(const uint8_t nist_sec_level) {
    switch(nist_sec_level) {
        case 1: return 16;
        case 3: return 24;
        case 5: return 32;
        default:
            // this implementation doesn't support any other
            // security level
            assert(false);
    }
}

// algs array stores parameters for all the instantiations
params_t algs[93] = {
    REG_ALG(FALCON512, HQCRMRS128, 1),
    REG_ALG(FALCON512, NTRUHPS2048509, 1),
    REG_ALG(FALCON512, LIGHTSABER, 1),
    REG_ALG(FALCON512, KYBER512, 1),
    REG_ALG(FALCON512, FRODOKEM640SHAKE, 1),
    REG_ALG(FALCON512, SIKE434, 1),
    REG_ALG(FALCON512, MCELIECE348864, 1),
    REG_ALG(SPHINCSSHA256128FSIMPLE, HQCRMRS128, 1),
    REG_ALG(SPHINCSSHA256128FSIMPLE, NTRUHPS2048509, 1),
    REG_ALG(SPHINCSSHA256128FSIMPLE, LIGHTSABER, 1),
    REG_ALG(SPHINCSSHA256128FSIMPLE, KYBER512, 1),
    REG_ALG(SPHINCSSHA256128FSIMPLE, FRODOKEM640SHAKE, 1),
    REG_ALG(SPHINCSSHA256128FSIMPLE, SIKE434, 1),
    REG_ALG(SPHINCSSHA256128FSIMPLE, MCELIECE348864, 1),
    REG_ALG(DILITHIUM2, HQCRMRS128, 1),
    REG_ALG(DILITHIUM2, NTRUHPS2048509, 1),
    REG_ALG(DILITHIUM2, LIGHTSABER, 1),
    REG_ALG(DILITHIUM2, KYBER512, 1),
    REG_ALG(DILITHIUM2, FRODOKEM640SHAKE, 1),
    REG_ALG(DILITHIUM2, SIKE434, 1),
    REG_ALG(DILITHIUM2, MCELIECE348864, 1),
    REG_ALG(RAINBOWICLASSIC, HQCRMRS128, 1),
    REG_ALG(RAINBOWICLASSIC, NTRUHPS2048509, 1),
    REG_ALG(RAINBOWICLASSIC, LIGHTSABER, 1),
    REG_ALG(RAINBOWICLASSIC, KYBER512, 1),
    REG_ALG(RAINBOWICLASSIC, FRODOKEM640SHAKE, 1),
    REG_ALG(RAINBOWICLASSIC, SIKE434, 1),
    REG_ALG(RAINBOWICLASSIC, MCELIECE348864, 1),
    REG_ALG(SPHINCSSHAKE256128FSIMPLE, HQCRMRS128, 1),
    REG_ALG(SPHINCSSHAKE256128FSIMPLE, NTRUHPS2048509, 1),
    REG_ALG(SPHINCSSHAKE256128FSIMPLE, LIGHTSABER, 1),
    REG_ALG(SPHINCSSHAKE256128FSIMPLE, KYBER512, 1),
    REG_ALG(SPHINCSSHAKE256128FSIMPLE, FRODOKEM640SHAKE, 1),
    REG_ALG(SPHINCSSHAKE256128FSIMPLE, SIKE434, 1),
    REG_ALG(SPHINCSSHAKE256128FSIMPLE, MCELIECE348864, 1),
    REG_ALG(DILITHIUM3, NTRUHPS2048677, 3),
    REG_ALG(DILITHIUM3, FRODOKEM976SHAKE, 3),
    REG_ALG(DILITHIUM3, KYBER768, 3),
    REG_ALG(DILITHIUM3, NTRUHRSS701, 3),
    REG_ALG(DILITHIUM3, HQCRMRS192, 3),
    REG_ALG(DILITHIUM3, MCELIECE460896, 3),
    REG_ALG(DILITHIUM3, SABER, 3),
    REG_ALG(RAINBOWIIICLASSIC, NTRUHPS2048677, 3),
    REG_ALG(RAINBOWIIICLASSIC, FRODOKEM976SHAKE, 3),
    REG_ALG(RAINBOWIIICLASSIC, KYBER768, 3),
    REG_ALG(RAINBOWIIICLASSIC, NTRUHRSS701, 3),
    REG_ALG(RAINBOWIIICLASSIC, HQCRMRS192, 3),
    REG_ALG(RAINBOWIIICLASSIC, MCELIECE460896, 3),
    REG_ALG(RAINBOWIIICLASSIC, SABER, 3),
    REG_ALG(SPHINCSSHAKE256192FSIMPLE, NTRUHPS2048677, 3),
    REG_ALG(SPHINCSSHAKE256192FSIMPLE, FRODOKEM976SHAKE, 3),
    REG_ALG(SPHINCSSHAKE256192FSIMPLE, KYBER768, 3),
    REG_ALG(SPHINCSSHAKE256192FSIMPLE, NTRUHRSS701, 3),
    REG_ALG(SPHINCSSHAKE256192FSIMPLE, HQCRMRS192, 3),
    REG_ALG(SPHINCSSHAKE256192FSIMPLE, MCELIECE460896, 3),
    REG_ALG(SPHINCSSHAKE256192FSIMPLE, SABER, 3),
    REG_ALG(SPHINCSSHA256192FSIMPLE, NTRUHPS2048677, 3),
    REG_ALG(SPHINCSSHA256192FSIMPLE, FRODOKEM976SHAKE, 3),
    REG_ALG(SPHINCSSHA256192FSIMPLE, KYBER768, 3),
    REG_ALG(SPHINCSSHA256192FSIMPLE, NTRUHRSS701, 3),
    REG_ALG(SPHINCSSHA256192FSIMPLE, HQCRMRS192, 3),
    REG_ALG(SPHINCSSHA256192FSIMPLE, MCELIECE460896, 3),
    REG_ALG(SPHINCSSHA256192FSIMPLE, SABER, 3),
    REG_ALG(FALCON1024, NTRUHPS4096821, 5),
    REG_ALG(FALCON1024, HQCRMRS256, 5),
    REG_ALG(FALCON1024, KYBER1024, 5),
    REG_ALG(FALCON1024, FIRESABER, 5),
    REG_ALG(FALCON1024, FRODOKEM1344SHAKE, 5),
    REG_ALG(FALCON1024, MCELIECE6688128, 5),
    REG_ALG(SPHINCSSHA256256FSIMPLE, NTRUHPS4096821, 5),
    REG_ALG(SPHINCSSHA256256FSIMPLE, HQCRMRS256, 5),
    REG_ALG(SPHINCSSHA256256FSIMPLE, KYBER1024, 5),
    REG_ALG(SPHINCSSHA256256FSIMPLE, FIRESABER, 5),
    REG_ALG(SPHINCSSHA256256FSIMPLE, FRODOKEM1344SHAKE, 5),
    REG_ALG(SPHINCSSHA256256FSIMPLE, MCELIECE6688128, 5),
    REG_ALG(RAINBOWVCLASSIC, NTRUHPS4096821, 5),
    REG_ALG(RAINBOWVCLASSIC, HQCRMRS256, 5),
    REG_ALG(RAINBOWVCLASSIC, KYBER1024, 5),
    REG_ALG(RAINBOWVCLASSIC, FIRESABER, 5),
    REG_ALG(RAINBOWVCLASSIC, FRODOKEM1344SHAKE, 5),
    REG_ALG(RAINBOWVCLASSIC, MCELIECE6688128, 5),
    REG_ALG(SPHINCSSHAKE256256FSIMPLE, NTRUHPS4096821, 5),
    REG_ALG(SPHINCSSHAKE256256FSIMPLE, HQCRMRS256, 5),
    REG_ALG(SPHINCSSHAKE256256FSIMPLE, KYBER1024, 5),
    REG_ALG(SPHINCSSHAKE256256FSIMPLE, FIRESABER, 5),
    REG_ALG(SPHINCSSHAKE256256FSIMPLE, FRODOKEM1344SHAKE, 5),
    REG_ALG(SPHINCSSHAKE256256FSIMPLE, MCELIECE6688128, 5),
    REG_ALG(DILITHIUM5, NTRUHPS4096821, 5),
    REG_ALG(DILITHIUM5, HQCRMRS256, 5),
    REG_ALG(DILITHIUM5, KYBER1024, 5),
    REG_ALG(DILITHIUM5, FIRESABER, 5),
    REG_ALG(DILITHIUM5, FRODOKEM1344SHAKE, 5),
    REG_ALG(DILITHIUM5, MCELIECE6688128, 5),
};

const size_t alg_num = ASZ(algs);
const params_t *get_alg_params(size_t i) {
    return &algs[i];
}

#define CHECK_PQC(expression)                               \
do {                                                        \
    bool stat__ = (expression);                             \
    if(stat__ != true) {                                    \
        fprintf(stderr, "ERROR[%d]: %s\n", stat__, #expression);\
        goto err;                                           \
    }                                                       \
} while(0)

// Self test checks if all needed tools are available.
void self_test() {
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
    hmac_state *hmac;
    int err;
    uint8_t sep[kResp] = {d};

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
    const pqc_ctx_t *kem_ctx = pqc_kem_alg_by_id(algs[alg_id].kem_id);
    const pqc_ctx_t *sig_ctx = pqc_sig_alg_by_id(algs[alg_id].sig_id);
    buf_init(&p->kem_eph_prv_key, algs[alg_id].kem_prv_sz);
    buf_init(&p->kem_keypair_static.pub_key, algs[alg_id].kem_pub_sz);
    buf_init(&p->kem_keypair_static.prv_key, algs[alg_id].kem_prv_sz);
    buf_init(&p->sig_keypair.pub_key, algs[alg_id].sig_pub_sz);
    buf_init(&p->sig_keypair.prv_key, algs[alg_id].sig_prv_sz);

    // generate long term signing and kem key
    CHECK_PQC(
        pqc_keygen(sig_ctx,
            p->sig_keypair.pub_key.p,
            p->sig_keypair.prv_key.p));
    CHECK_PQC(
        pqc_keygen(kem_ctx,
            p->kem_keypair_static.pub_key.p, p->kem_keypair_static.prv_key.p));
    p->role = role;
    p->alg_id = alg_id;

    RAND_bytes(tmp, ASZ(tmp));
    ext_s(p->ident, IDENT_LEN, tmp, &p->kem_keypair_static.prv_key);
    ret = true;

err:
    if (!ret) {
        buf_free(&p->kem_eph_prv_key);
        buf_free(&p->kem_keypair_static.pub_key);
        buf_free(&p->kem_keypair_static.prv_key);
        buf_free(&p->sig_keypair.pub_key);
        buf_free(&p->sig_keypair.prv_key);
    }
    return ret;
}

void clean_party(part_t *p) {
    buf_free(&p->kem_eph_prv_key);
    buf_free(&p->kem_keypair_static.pub_key);
    buf_free(&p->kem_keypair_static.prv_key);
    buf_free(&p->sig_keypair.pub_key);
    buf_free(&p->sig_keypair.prv_key);
}

void init_session(comm_ctx_t *c, part_t p[2]) {
    assert(p[kInit].alg_id == p[kResp].alg_id);

    c->params = &algs[p[kInit].alg_id];
    c->kem_ctx = pqc_kem_alg_by_id(c->params->kem_id);
    c->sig_ctx = pqc_sig_alg_by_id(c->params->sig_id);
    RAND_bytes(c->seed, ASZ(c->seed));

    assert(c->kem_ctx);
    assert(c->sig_ctx);

    // Init all the memory used
    buf_init(&c->sid_pfx, c->params->sid_pfx_sz);
    buf_init(&c->i.kem_static, c->params->kem_pub_sz);
    buf_init(&c->i.sig, c->params->sig_pub_sz);
    buf_init(&c->i.kem_eph, c->params->sig_pub_sz);
    buf_init(&c->r.pub_key_eph, c->params->kem_pub_sz);
    buf_init(&c->i.sign_A, c->params->sig_sz);
    buf_init(&c->r.ct_st, c->params->kem_ct_sz);
    buf_init(&c->r.ct_eph, c->params->kem_ct_sz);
    buf_init(&c->r.sign, c->params->sig_sz);
    buf_init(&c->w.sid, c->params->sid_sz);
    buf_init(&c->w.ss_st, c->params->kem_ss_sz);
    buf_init(&c->w.ss_eph, c->params->kem_ss_sz);

    // Concatenate initial part of session ID: P_i||P_j||lpk_i||lpk_j
    uint8_t *psid = c->sid_pfx.p;
    memcpy(psid, p[kInit].ident, ASZ(p[kInit].ident));
    psid += ASZ(p[kInit].ident);
    memcpy(psid, p[kResp].ident, ASZ(p[kResp].ident));
    psid += ASZ(p[kResp].ident);

    // lpk_i
    copy_from_buf(psid, p[kInit].kem_keypair_static.pub_key.sz, &p[kInit].kem_keypair_static.pub_key);
    psid += p[kInit].kem_keypair_static.pub_key.sz;

    copy_from_buf(psid, p[kInit].sig_keypair.pub_key.sz, &p[kInit].sig_keypair.pub_key);
    psid += p[kInit].sig_keypair.pub_key.sz;

    // lpk_j
    copy_from_buf(psid, p[kResp].kem_keypair_static.pub_key.sz, &p[kResp].kem_keypair_static.pub_key);
    psid += p[kResp].kem_keypair_static.pub_key.sz;
    copy_from_buf(psid, p[kResp].sig_keypair.pub_key.sz, &p[kResp].sig_keypair.pub_key);
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
    // set parameters for all registered algorithms
    for(size_t i=0; i<alg_num; i++) {
        register_algo(&algs[i],
            pqc_sig_alg_by_id(algs[i].sig_id),
            pqc_kem_alg_by_id(algs[i].kem_id));
    }
    self_test();
}

static void finish_sid(buf_t *sid, const comm_ctx_t *c) {
    uint8_t *psid = sid->p;
    copy_from_buf(psid, c->sid_pfx.sz, &c->sid_pfx);
    psid += c->params->sid_pfx_sz;

    // ek_t
    copy_from_buf(psid, c->r.pub_key_eph.sz, &c->r.pub_key_eph);
    psid += c->r.pub_key_eph.sz;

    // ct
    copy_from_buf(psid, c->r.ct_st.sz, &c->r.ct_st);
    psid += c->r.ct_st.sz;

    // ct_eph
    copy_from_buf(psid, c->r.ct_eph.sz, &c->r.ct_eph);
}

bool offer(comm_ctx_t *c, /*const*/part_t *p) {
    // store ephemeral KEM public key in session and keep private key local
    CHECK_PQC(
        pqc_keygen(c->kem_ctx,
            c->r.pub_key_eph.p,
            p->kem_eph_prv_key.p));
    // Create sigma A, by signing public, ephmeral key ekT key and store sign in the session
    CHECK_PQC(
        pqc_sig_create(c->sig_ctx,
            c->i.sign_A.p, &c->i.sign_A.sz,
            c->r.pub_key_eph.p, c->r.pub_key_eph.sz,
            p->sig_keypair.prv_key.p));
    return
        copy_buf(&c->i.sig, &p->sig_keypair.pub_key) &&
        copy_buf(&c->i.kem_static, &p->kem_keypair_static.pub_key);
err:
    return false;
}

bool accept(uint8_t *session_key, comm_ctx_t *c, const part_t *p) {
    buf_t *ss_st = &c->w.ss_st;
    buf_t *ss_eph = &c->w.ss_eph;
    buf_t *sid = &c->w.sid;
    uint8_t concat_sess_key[MAX_KJKH_LEN] = {0};

    // Verify sigma A
    CHECK_PQC(
        pqc_sig_verify(c->sig_ctx,
            c->i.sign_A.p, c->i.sign_A.sz,
            c->r.pub_key_eph.p, c->r.pub_key_eph.sz,
            c->i.sig.p));

    CHECK_PQC(
        pqc_kem_encapsulate(c->kem_ctx,
            c->r.ct_st.p, ss_st->p,
            c->i.kem_static.p));

    CHECK_PQC(
        pqc_kem_encapsulate(c->kem_ctx,
            c->r.ct_eph.p, ss_eph->p,
            c->r.pub_key_eph.p));

    finish_sid(sid, c);

    CHECK_PQC(
        pqc_sig_create(c->sig_ctx,
            c->r.sign.p, &c->r.sign.sz,
            sid->p, sid->sz,
            p->sig_keypair.prv_key.p));

    const size_t sec_len = get_kem_security_bytelen(c->params->nist_level);
    get_session_key(concat_sess_key, c->seed, sid, ss_st, ss_eph, sec_len,
        c->r.sign.sz);

    // sigma = c XOR kh
    for (size_t i=0; i<c->r.sign.sz; i++) {
        c->r.sign.p[i] ^= concat_sess_key[sec_len+i];
    }
    copy_buf(&c->i.kem_eph, &p->sig_keypair.pub_key);

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
    CHECK_PQC(
        pqc_kem_decapsulate(c->kem_ctx,
            ss_st->p, c->r.ct_st.p,
            p->kem_keypair_static.prv_key.p));

    CHECK_PQC(
        pqc_kem_decapsulate(c->kem_ctx,
            ss_eph->p, c->r.ct_eph.p,
            p->kem_eph_prv_key.p));


    const size_t sec_len = get_kem_security_bytelen(c->params->nist_level);
    get_session_key(concat_sess_key, c->seed, sid, ss_st, ss_eph, sec_len,
        c->r.sign.sz);

    // sigma = c XOR kh
    for (size_t i=0; i<c->r.sign.sz; i++) {
        c->r.sign.p[i] ^= concat_sess_key[sec_len+i];
    }

    CHECK_PQC(
        pqc_sig_verify(c->sig_ctx,
            c->r.sign.p, c->r.sign.sz,
            sid->p, sid->sz,
            c->i.kem_eph.p));

    // copy-out k_i
    memcpy(session_key, concat_sess_key, sec_len);

    return true;
err:
    return false;
}

void clean_session(comm_ctx_t *c) {
    buf_free(&c->sid_pfx);
    buf_free(&c->i.kem_static);
    buf_free(&c->i.sig);
    buf_free(&c->i.kem_eph);
    buf_free(&c->r.pub_key_eph);
    buf_free(&c->i.sign_A);
    buf_free(&c->r.ct_st);
    buf_free(&c->r.ct_eph);
    buf_free(&c->r.sign);
    buf_free(&c->w.sid);
    buf_free(&c->w.ss_st);
    buf_free(&c->w.ss_eph);
}

static inline size_t lpk(const comm_ctx_t *c) {
    return c->params->kem_pub_sz + c->params->sig_pub_sz;
}

size_t get_received_init_data_len(const comm_ctx_t *c) {
    return lpk(c);
}

size_t get_scheme_sec(const comm_ctx_t *c) {
    return c->params->nist_level;
}

size_t get_i2s(const comm_ctx_t *c) {
    return c->params->kem_pub_sz + c->params->sig_sz;
}

size_t get_s2r(const comm_ctx_t *c) {
    return get_i2s(c) + lpk(c);
}

size_t get_r2s(const comm_ctx_t *c) {
    return (2*c->params->kem_ct_sz) + c->params->sig_sz;
}

size_t get_s2i(const comm_ctx_t *c) {
    return get_r2s(c) + lpk(c);
}

size_t get_static_data_size(const comm_ctx_t *c) {
    return lpk(c) + c->params->kem_pub_sz + c->params->sig_sz;
}

size_t get_session_est_data_size(const comm_ctx_t *c) {
    return get_r2s(c);
}
