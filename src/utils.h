#ifndef UTILS_H_
#define UTILS_H_

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Returns number of elements in an array a
#define ASZ(a) ((sizeof((a))) / sizeof((a)[0]))

/* Concatenate tokens X and Y. Can be done by the "##" operator in
 * simple cases, but has some side effects in more complicated cases.
 */
#define GLUE(a, b) GLUE_(a, b)
#define GLUE_(a, b) a##b

// Stringify constants
#define STR(x) STR_(x)
#define STR_(x) #x

// Max. length of the security (NIST level 5 gives 256-bit => 32 bytes)
#define MAX_SEC_BYTE_LEN 32U
// Picnic3_L5 has the longest signature size
#define MAX_SIG_LEN 61028U
// Max length for k_j||k = F_k1(sid_j) XOR F_k2(sid_j)
#define MAX_KJKH_LEN (MAX_SEC_BYTE_LEN+MAX_SIG_LEN)

// stores buffer, it's current length and max possible length
typedef struct buf_t {
    // pointer to the data buffer
    uint8_t *p;
    // amount of data in the buffer
    size_t sz;
} buf_t;

/**
 * Initialize buffer |b|. The buffer will be able to store max
 * |sz| bytes of data. Returns 1 on success otherwise 0.
 */
int buf_init(buf_t *b, size_t sz);

// Frees memory allocated for b. 'b' can be NULL
void buf_free(buf_t *b);

/**
 * Copies data from |z| to |p|. |p| must be allocated and big enough
 * to store data form |z|. Size of the |p| is indicated by |sz|. On
 * error returns 0, otherwise number of copied bytes.
 */
size_t copy_from_buf(uint8_t *p, size_t sz, const buf_t *z);

/**
 * Copies |sz| bytes of data from |p| into |z|. |z| must be allocated
 * with buf_init() and big enough to store |sz| bytes. It number of bytes
 * allocated, which is 0 in case of an error.
 */
size_t copy_to_buf(buf_t *b, const uint8_t *p, size_t sz);

size_t copy_buf(buf_t *out, const buf_t *in);
#endif
