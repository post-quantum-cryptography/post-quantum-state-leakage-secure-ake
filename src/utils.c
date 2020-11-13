#include "utils.h"

size_t
copy_from_buf(uint8_t *p, size_t sz, const buf_t *z) {
    if (sz < z->sz) {
        return 0;
    }
    memcpy(p, z->p, z->sz);
    return z->sz;
}

size_t
copy_to_buf(buf_t *b, const uint8_t *p, size_t sz) {
    if (sz > b->sz) {
        return 0;
    }
    memcpy(b->p, p, sz);
    b->sz = sz;
    return sz;
}

size_t
copy_buf(buf_t *out, const buf_t *in) {
    if (out->sz < in->sz) {
        return 0;
    }
    memcpy(out->p, in->p, in->sz);
    out->sz = in->sz;
    return out->sz;
}

int
buf_init(buf_t *b, size_t sz) {
    b->p = malloc(sz);
    b->sz = sz;
    return !!b->p;
}

void
buf_free(buf_t *b) {
    if (!b) {
        return;
    }
    free(b->p);
    b->sz = 0;
}
