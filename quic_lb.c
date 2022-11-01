/*
 * Copyright (c) 2020 F5 Networks Inc.
 * This source code is subject to the terms of the Apache License,
 * version 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 */
#include <math.h>
#include <openssl/evp.h>
#include "quic_lb.h"
#ifndef NOBIGIP
#include <openssl/evp.h>
#include <local/sys/cpu.h>
#include <local/sys/debug.h>
#include <local/sys/def.h>
#include <local/sys/err.h>
#include <local/sys/lib.h>
#include <local/sys/rnd.h>
#include <local/sys/umem.h>
#endif

#define QUIC_LB_TUPLE_ROUTE 0xc0
#define QUIC_LB_USABLE_BYTES (QUIC_LB_MAX_CID_LEN - 1)

/* Parameter limits */
#define QUIC_LB_BLOCK_SIZE 16
#define QUIC_LB_NONCE_MIN 4

typedef UINT8 QUIC_LB_BLOCK[QUIC_LB_BLOCK_SIZE];

#define CIDL(cfg) ((cfg)->sidl + (cfg)->nonce_len + 1)

struct quic_lb_lb_ctx {
    UINT8       cr : 2;
    UINT8       encode_length : 1;
    size_t      sidl;
    size_t      nonce_len;
    void       *crypto_ctx;
};

struct quic_lb_server_ctx {
    UINT8            cr : 2;
    UINT8            encode_length : 1;
    size_t           sidl;
    size_t           nonce_len;
    void            *crypto_ctx;

    UINT8            sid[QUIC_LB_USABLE_BYTES];
    UINT128          nonce_ctr; /* counter for nonce */
    UINT128          orig_nonce; /* time to stop using this config */
};

static void
quic_lb_set_first_octet(struct quic_lb_server_ctx *ctx, UINT8 *ptr)
{
    if (ctx->encode_length) {
        *ptr = CIDL(ctx) - 1;
    } else {
        rndset(ptr, RND_PSEUDO, 1);
    }
    *ptr &= 0x3f;
    *ptr |= (ctx->cr << 6);
}

/* Helper functions for 4-pass encryption */
static void
quic_lb_truncate_left(QUIC_LB_BLOCK left, QUIC_LB_BLOCK block, size_t inlen) 
{
    // Copy what we can evenly
    memcpy(left, block, inlen / 2);

    if ((inlen % 2) != 0) {
        size_t unfriendly = (inlen / 2);
        left[unfriendly] = (block[unfriendly] & 0xf0);
    }
}

static void
quic_lb_truncate_right(QUIC_LB_BLOCK right, QUIC_LB_BLOCK block, size_t inlen)
{
    memcpy(right, block + (inlen / 2), inlen / 2);
    if ((inlen % 2) == 1) {
        right[inlen/2] = block[inlen - 1];;
        right[0] &= 0x0f;
    }
}

static void
quic_lb_encrypt_pass(void *crypto_ctx, QUIC_LB_BLOCK side_to_encrypt,
        QUIC_LB_BLOCK side_to_xor, UINT8 total_len, UINT8 block_id) 
{
    size_t side_len = ceilf(total_len / 2.0);
    int ct_len = 0;

    QUIC_LB_BLOCK scratch = { 0 };
    scratch[0] = total_len;
    scratch[1] = block_id;
    memcpy(&scratch[2], side_to_encrypt, side_len);
    if (EVP_EncryptUpdate(crypto_ctx, scratch, &ct_len, scratch,
            QUIC_LB_BLOCK_SIZE) != 1) {
        printf("EVP_EncryptUpdate (AES) failed.\n");
        return;
    }
    for (int i = 0; i < side_len; i++) {
        side_to_xor[i] ^= scratch[i];
    }
}

void *
quic_lb_lb_ctx_init(BOOL encode_len, size_t sidl, UINT8 *key,
        size_t nonce_len)
{
    struct quic_lb_lb_ctx *ctx = umalloc(sizeof(struct quic_lb_lb_ctx),
            M_FILTER, UM_ZERO);

    if (ctx == NULL) {
        goto fail;
    }
    ctx->crypto_ctx = NULL;
    ctx->encode_length = encode_len;
    if ((sidl == 0) || (nonce_len < 4) ||
            ((sidl + nonce_len) > QUIC_LB_USABLE_BYTES)) {
        goto fail;
    }
    ctx->sidl = sidl;
    ctx->nonce_len = nonce_len;
    if (key == NULL) {
        return ctx;
    }
    ctx->crypto_ctx = EVP_CIPHER_CTX_new();
    if (ctx->crypto_ctx == NULL) {
        goto fail;
    }
    /*
     * CTR mode just encrypts the nonce using AES-ECB and XORs it with
     * the plaintext or ciphertext. So for SCID the decryption
     * operation is technically an encryption (the last arg is 1).
     */
    if (EVP_CipherInit_ex(ctx->crypto_ctx, EVP_aes_128_ecb(), NULL, key,
              NULL, (sidl + nonce_len == QUIC_LB_BLOCK_SIZE) ? 0 : 1) == 0)
    {
        goto fail;
    }
    if (EVP_CIPHER_CTX_set_padding(ctx->crypto_ctx, 0) == 0) {
        goto fail;
    }
    return ctx;
fail:
    if (ctx != NULL) {
        if (ctx->crypto_ctx != NULL) {
            EVP_CIPHER_CTX_free(ctx->crypto_ctx);
        }
        ufree(ctx);
    }
    return NULL;
}

void *
quic_lb_server_ctx_init(UINT8 cr, BOOL encode_len, size_t sidl, UINT8 *key,
        size_t nonce_len, UINT8 *sid)
{
    struct quic_lb_server_ctx *ctx = umalloc(
            sizeof(struct quic_lb_server_ctx), M_FILTER, UM_ZERO);

    if (ctx == NULL) {
        goto fail;
    }
    ctx->crypto_ctx = NULL;
    if (cr > 0x2) {
        goto fail;
    }
    ctx->cr = cr;
    ctx->encode_length = encode_len;
    if ((sidl == 0) || (nonce_len < 4) ||
            ((sidl + nonce_len) > QUIC_LB_USABLE_BYTES)) {
        goto fail;
    }
    ctx->sidl = sidl;
    ctx->nonce_len = nonce_len;
    ctx->nonce_ctr = 0;
    rndset(&(ctx->nonce_ctr), RND_PSEUDO, nonce_len);
    memcpy(&(ctx->orig_nonce), &(ctx->nonce_ctr), sizeof(ctx->nonce_ctr));
    ctx->nonce_ctr++; /* When nonce_ctr == orig_nonce, quit */
    memcpy(ctx->sid, sid, sidl);
    if (key == NULL) {
        return ctx;
    }
    ctx->crypto_ctx = EVP_CIPHER_CTX_new();
    if (ctx->crypto_ctx == NULL) {
        goto fail;
    }
    if (EVP_CipherInit_ex(ctx->crypto_ctx, EVP_aes_128_ecb(), NULL, key,
            NULL, 1) == 0) {
        EVP_CIPHER_CTX_free(ctx->crypto_ctx);
        goto fail;
    }
    if (EVP_CIPHER_CTX_set_padding(ctx->crypto_ctx, 0) == 0) {
        goto fail;
    }
    return ctx;
fail:
    if (ctx != NULL) {
        if (ctx->crypto_ctx != NULL) {
            EVP_CIPHER_CTX_free(ctx->crypto_ctx);
        }
        ufree(ctx);
    }
    return NULL;
}

void
quic_lb_lb_ctx_free(void *ctx)
{
    struct quic_lb_lb_ctx *todelete = (struct quic_lb_lb_ctx *)ctx;

    if (todelete->crypto_ctx != NULL) {
        EVP_CIPHER_CTX_free(todelete->crypto_ctx);
    }
    ufree(ctx);
}

void
quic_lb_server_ctx_free(void *ctx)
{
    struct quic_lb_server_ctx *todelete = (struct quic_lb_server_ctx *)ctx;

    if (todelete->crypto_ctx != NULL) {
        EVP_CIPHER_CTX_free(todelete->crypto_ctx);
    }
    ufree(ctx);
}

void
quic_lb_encrypt_cid(void *ctx, void *cid)
{
    struct quic_lb_server_ctx *cfg = ctx;
    UINT8 *ptr = cid;
    int ct_len;
    size_t total_len = cfg->sidl + cfg->nonce_len;
    /* State variables for 4-pass encryption */
    QUIC_LB_BLOCK left = { 0 }, right = { 0 };

    if ((cfg == NULL) ||
            (memcmp(&(cfg->nonce_ctr), &(cfg->orig_nonce),
                    cfg->nonce_len) == 0)) {
        goto err;
    }
    quic_lb_set_first_octet(cfg, ptr);
    ptr++;
    memcpy(ptr, cfg->sid, cfg->sidl);
    ptr += cfg->sidl;
    if (cfg == NULL) {
        rndset(ptr, RND_PSEUDO, cfg->nonce_len);
        goto done;
    }
    memcpy(ptr, &(cfg->nonce_ctr), cfg->nonce_len);
    cfg->nonce_ctr++;
    ptr -= cfg->sidl;
    if (total_len == QUIC_LB_BLOCK_SIZE) {
        if ((EVP_EncryptUpdate(cfg->crypto_ctx, ptr, &ct_len, ptr,
                 total_len) != 1) || (ct_len != total_len)) {
            goto err;
        }
        goto done;
    }
    /* 4-pass encryption */
    quic_lb_truncate_left(left, ptr, total_len);
    quic_lb_truncate_right(right, ptr, total_len);

    quic_lb_encrypt_pass(cfg->crypto_ctx, left, right, total_len, 1);
    if (total_len % 2 == 1) {
        right[0] &= 0x0f;
    }
    quic_lb_encrypt_pass(cfg->crypto_ctx, right, left, total_len, 2);
    if (total_len % 2 == 1) {
        left[total_len / 2] &= 0xf0;
    }
    quic_lb_encrypt_pass(cfg->crypto_ctx, left, right, total_len, 3);
    if (total_len % 2 == 1) {
        right[0] &= 0x0f;
    }
    quic_lb_encrypt_pass(cfg->crypto_ctx, right, left, total_len, 4);
    if (total_len % 2 == 1) {
        left[total_len / 2] &= 0xf0;
    }

    memcpy(ptr, left, total_len / 2);
    ptr += total_len / 2;
    if (total_len % 2 == 1) {
        *ptr = left[total_len / 2] & 0xf0;
        *ptr |= (right[0] & 0x0f);
        ptr++;
    }
    memcpy(ptr, right + (total_len % 2), total_len / 2);
done:
    return;
err:
    rndset(cid, RND_PSEUDO, 8);
    *(UINT8 *)cid |= QUIC_LB_TUPLE_ROUTE;
    return;
}

int
quic_lb_decrypt_cid(void *ctx, void *cid, void *sid, size_t *cid_len)
{
    struct quic_lb_server_ctx *cfg = ctx;
    UINT8 *ptr = cid;
    int pt_len;
    size_t total_len = cfg->sidl + cfg->nonce_len;
    /* State variables for 4-pass encryption */
    QUIC_LB_BLOCK left = { 0 }, right = { 0 };

    if (cfg == NULL) {
        goto err;
    }
    if (cfg->encode_length) {
        *cid_len = (size_t)(*ptr & 0x3f) + 1;
    }
    ptr++;
    if (cfg->crypto_ctx == NULL) {
        memcpy(sid, ptr, cfg->sidl);
        goto done;
    }
    if (total_len == QUIC_LB_BLOCK_SIZE) {
        if ((EVP_DecryptUpdate(cfg->crypto_ctx, left, &pt_len, ptr,
                total_len) != 1) || (pt_len != total_len)) {
            goto err;
        }
        memcpy(sid, left, cfg->sidl);
        goto done;
    }
    /* 4-pass encryption */
    quic_lb_truncate_left(left, ptr, total_len);
    quic_lb_truncate_right(right, ptr, total_len);

    quic_lb_encrypt_pass(cfg->crypto_ctx, right, left, total_len, 4);
    if (total_len % 2 == 1) {
        left[total_len / 2] &= 0xf0;
    }
    quic_lb_encrypt_pass(cfg->crypto_ctx, left, right, total_len, 3);
    if (total_len % 2 == 1) {
        right[0] &= 0x0f;
    }
    quic_lb_encrypt_pass(cfg->crypto_ctx, right, left, total_len, 2);
    if (total_len % 2 == 1) {
        left[total_len / 2] &= 0xf0;
    }
    if (cfg->sidl > cfg->nonce_len) {
        quic_lb_encrypt_pass(cfg->crypto_ctx, left, right, total_len, 1);
        if (total_len % 2 == 1) {
            right[0] &= 0x0f;
        }
    }

    if (cfg->sidl <= total_len / 2) {
        memcpy(sid, left, cfg->sidl);
        goto done;
    }
    memcpy(sid, left, total_len/2);
    ptr = sid + total_len / 2;
    if (total_len % 2 == 1) {
        *ptr = left[total_len/2] | right[0];
        ptr++;
    }
    memcpy(ptr, right + (total_len % 2), cfg->sidl - (ptr - (UINT8 *)sid));
done:
    return cfg->sidl;
err:
    return 0;
}

void
test_quic_lb_truncate()
{
    QUIC_LB_BLOCK result_buffer = { 0 };

    QUIC_LB_BLOCK test0 = { 0x31, 0x44, 0x1a, 0x9c, 0x69, 0xc2, 0x75 };
    QUIC_LB_BLOCK test0_left = { 0x31, 0x44, 0x1a, 0x90 };
    QUIC_LB_BLOCK test0_right = { 0x0c, 0x69, 0xc2, 0x75 };

    QUIC_LB_BLOCK test1 = { 0x12 };
    QUIC_LB_BLOCK test1_left = { 0x10 };
    QUIC_LB_BLOCK test1_right = { 0x02 };

    QUIC_LB_BLOCK test2 = { 0x00, 0x11 };
    QUIC_LB_BLOCK test2_left = { 0x00 };
    QUIC_LB_BLOCK test2_right = { 0x11 };

    typedef struct {
        QUIC_LB_BLOCK *input, *left, *right;
        size_t len;
    } _QUIC_LB_TRUNCATE_TEST;

    _QUIC_LB_TRUNCATE_TEST tests[] = {
        { &test0, &test0_left, &test0_right, 7 },
        { &test1, &test1_left, &test1_right, 1 },
        { &test2, &test2_left, &test2_right, 2 },
    };

    for (int i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        memset(result_buffer, '\0', sizeof(result_buffer));

        _QUIC_LB_TRUNCATE_TEST *test = &tests[0];

        quic_lb_truncate_left(result_buffer, *test->input, test->len);
        if (memcmp(result_buffer, test->left, ceilf(test->len / 2.0)) !=
                0) {
            printf("Truncate_left test failed %d\n", i);
        }

        memset(result_buffer, '\0', sizeof(result_buffer));

        quic_lb_truncate_right(result_buffer, *test->input, test->len);
        if (memcmp(result_buffer, test->right, ceilf(test->len / 2.0)) !=
                0) {
            printf("Truncate_right test failed %d\n", i);
        }
    }
}
