/*
 * Copyright (c) 2020 F5 Networks Inc.
 * This source code is subject to the terms of the Apache License,
 * version 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 */
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

#define CIDL(cfg) ((cfg)->sidl + (cfg)->nonce_len + 1)

struct quic_lb_lb_ctx {
    UINT8       cr : 2;
    UINT8       encode_length : 1;
    enum quic_lb_alg alg : 2;
    UINT8       reserved : 3;
    size_t      sidl;
    int       (*decrypt)(void *ctx, void *cid, void *sid, size_t *cid_len);
    void       *crypto_ctx;
    size_t      nonce_len;
};

struct quic_lb_server_ctx {
    UINT8            cr : 2;
    UINT8            encode_length : 1;
    enum quic_lb_alg alg : 5;
    size_t           sidl;
    UINT8            sid[QUIC_LB_USABLE_BYTES];
    void           (*encrypt)(void *ctx, void *cid);
    void            *crypto_ctx;
    size_t           nonce_len;
    UINT128          nonce_ctr; /* counter for nonce */
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

/* Algorithm-specific functions */
static void
quic_lb_pcid_encrypt(void *ctx, void *cid)
{
    struct quic_lb_server_ctx *cfg = ctx;
    UINT8 *ptr = cid;

    quic_lb_set_first_octet(cfg, ptr);
    ptr++;
    memcpy(ptr, cfg->sid, cfg->sidl);
    ptr += cfg->sidl;
    rndset(ptr, RND_PSEUDO, cfg->nonce_len);
    return;
}

static int
quic_lb_pcid_decrypt(void *ctx, void *cid, void *sid, size_t *cid_len)
{
    struct quic_lb_lb_ctx *cfg = ctx;
    UINT8 *ptr = cid;

    if (cfg->encode_length) {
        *cid_len = (size_t)(*ptr & 0x3f) + 1;
    }
    ptr++;
    memcpy(sid, ptr, cfg->sidl);
    return cfg->sidl;
}

static inline err_t
quic_lb_encrypt_apply_nonce(void *crypto_ctx, UINT8 *nonce, UINT8 nonce_len,
        UINT8 *target, UINT8 target_len)
{
    UINT8 pt[QUIC_LB_BLOCK_SIZE];
    UINT8 ct[QUIC_LB_BLOCK_SIZE];
    int ct_len, i;

    memset(pt, 0, sizeof(pt));
    memcpy(pt, nonce, nonce_len);
    if (EVP_EncryptUpdate(crypto_ctx, ct, &ct_len, pt, sizeof(pt)) !=
            1) {
        goto err;
    }
    if (ct_len != sizeof(pt)) {
        goto err;
    }
    for (i = 0; i < target_len; i++) {
        *(target + i) = ct[i] ^ target[i];
    }
    return ERR_OK;
err:
    return ERR_REJECT;
}

static void
quic_lb_scid_encrypt(void *ctx, void *cid)
{
    struct quic_lb_server_ctx *cfg = ctx;
    UINT8  *sid = (UINT8 *)cid + 1, *nonce = sid + cfg->sidl;

    if (cfg->nonce_ctr > ((((UINT128)0x1 << cfg->nonce_len * 8)) - 1)) {
        /* Nonce is not big enough for unique CIDs */
        goto err;
    }
    quic_lb_set_first_octet(cfg, (UINT8 *)cid);
    memcpy(sid, cfg->sid, cfg->sidl);
    memcpy(nonce, &cfg->nonce_ctr, cfg->nonce_len); /* Host order! */
    /* 1st Pass */
    if (quic_lb_encrypt_apply_nonce(cfg->crypto_ctx, nonce, cfg->nonce_len,
	    sid, cfg->sidl) != ERR_OK) {
        goto err;
    }
    /* 2nd Pass */
    if (quic_lb_encrypt_apply_nonce(cfg->crypto_ctx, sid, cfg->sidl, nonce,
            cfg->nonce_len) != ERR_OK) {
        goto err;
    }
    /* 3rd Pass */
    if (quic_lb_encrypt_apply_nonce(cfg->crypto_ctx, nonce, cfg->nonce_len,
	    sid, cfg->sidl) != ERR_OK) {
        goto err;
    }
    cfg->nonce_ctr++;
    return;
err:
    /* Go to 5-tuple routing*/
    rndset(cid, RND_PSEUDO, CIDL(cfg));
    *(UINT8 *)cid &= 0xc0;
    return;
}

static int
quic_lb_scid_decrypt(void *ctx, void *cid, void *sid, size_t *cid_len)
{
    struct quic_lb_lb_ctx *cfg = ctx;
    UINT8 *read = cid;
    UINT8 nonce[cfg->nonce_len];

    if (cfg->encode_length) {
        *cid_len = (size_t)(*(UINT8 *)cid & 0x3f) + 1;
    }
    read++;
    memcpy(sid, read, cfg->sidl);
    memcpy(nonce, read + cfg->sidl, cfg->nonce_len);
    /* 1st Pass */
    if (quic_lb_encrypt_apply_nonce(cfg->crypto_ctx, nonce, cfg->nonce_len,
             sid, cfg->sidl) != ERR_OK) {
        goto err;
    }
    /* 2nd Pass */
    if (quic_lb_encrypt_apply_nonce(cfg->crypto_ctx, sid, cfg->sidl, nonce,
            cfg->nonce_len) != ERR_OK) {
        goto err;
    }
    /* 3rd Pass */
    if (quic_lb_encrypt_apply_nonce(cfg->crypto_ctx, nonce, cfg->nonce_len,
            sid, cfg->sidl) != ERR_OK) {
        goto err;
    }
    return cfg->sidl;
err:
    return 0;
}

static void
quic_lb_bcid_encrypt(void *ctx, void *cid)
{
    struct quic_lb_server_ctx *cfg = ctx;
    UINT8 *ptr = cid;
    UINT8 block[QUIC_LB_BLOCK_SIZE];
    UINT8 ct_nonce_len = QUIC_LB_BLOCK_SIZE - cfg->sidl;
    int ct_len;

    if (cfg->nonce_ctr > (((UINT128)0x1 << (ct_nonce_len * 8)) - 1)) {
        /* Nonce is not big enough for unique CIDs */
        goto err;
    }
    quic_lb_set_first_octet(cfg, ptr);
    ptr++;
    memcpy(&block[0], cfg->sid, cfg->sidl);
    /* Note: call below relies on nonce_ctr in host order */
    memcpy(&block[cfg->sidl], &(cfg->nonce_ctr), ct_nonce_len);
    if ((EVP_EncryptUpdate(cfg->crypto_ctx, ptr, &ct_len, block,
             sizeof(block)) != 1) || (ct_len != sizeof(block))) {
        goto err;
    }
    rndset(ptr + sizeof(block), RND_PSEUDO, cfg->nonce_len - ct_nonce_len);
    cfg->nonce_ctr++;
    return;
err:
    /* Go to 5-tuple routing*/
    rndset(cid, RND_PSEUDO, CIDL(cfg));
    *(UINT8 *)cid &= 0xc0;
    return;
}

static int
quic_lb_bcid_decrypt(void *ctx, void *cid, void *sid, size_t *cid_len)
{
    struct quic_lb_lb_ctx *cfg = ctx;
    UINT8 *ptr = cid;
    UINT8 block[QUIC_LB_BLOCK_SIZE];
    int pt_len;

    if (cfg->encode_length) {
        *cid_len = (size_t)(*(UINT8 *)cid & 0x3f) + 1;
    }
    if ((EVP_DecryptUpdate(cfg->crypto_ctx, &block[0], &pt_len, ptr + 1,
            sizeof(block)) != 1) || (pt_len != sizeof(block))) {
        goto err;
    }
    memcpy(sid, block, cfg->sidl);
    return cfg->sidl;
err:
    return 0;
}

void *
quic_lb_lb_ctx_init(enum quic_lb_alg alg, BOOL encode_len, size_t sidl,
        UINT8 *key, size_t nonce_len)
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
    switch (alg) {
    case QUIC_LB_PCID:
        ctx->decrypt = quic_lb_pcid_decrypt;
        break;
    case QUIC_LB_BCID:
	if ((sidl + nonce_len) < QUIC_LB_BLOCK_SIZE) {
	    goto fail;
	}
	/* Fall through */
    case QUIC_LB_SCID:
        ctx->decrypt = (alg == QUIC_LB_BCID) ? quic_lb_bcid_decrypt :
		quic_lb_scid_decrypt;
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
                 NULL, (alg == QUIC_LB_BCID) ? 0 : 1) == 0) {
            goto fail;
        }
        if (EVP_CIPHER_CTX_set_padding(ctx->crypto_ctx, 0) == 0) {
            goto fail;
        }
        break;
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
quic_lb_server_ctx_init(enum quic_lb_alg alg, UINT8 cr, BOOL encode_len,
        size_t sidl, UINT8 *key, size_t nonce_len, UINT8 *sid)
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
    memcpy(ctx->sid, sid, sidl);
    switch (alg) {
    case QUIC_LB_PCID:
        ctx->encrypt = quic_lb_pcid_encrypt;
        break;
    case QUIC_LB_BCID:
        if (sidl + nonce_len > QUIC_LB_USABLE_BYTES) {
            goto fail;
        }
	/* Fall through */
    case QUIC_LB_SCID:
        ctx->encrypt = (alg == QUIC_LB_BCID) ? quic_lb_bcid_encrypt :
		quic_lb_scid_encrypt;
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
        break;
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
    struct quic_lb_server_ctx *context = ctx;

    if (context == NULL) {
        rndset(cid, RND_PSEUDO, 8);
        *(UINT8 *)cid |= QUIC_LB_TUPLE_ROUTE;
    } else {
        context->encrypt(ctx, cid);
    }
}

int
quic_lb_decrypt_cid(void *ctx, void *cid, void *sid, size_t *cid_len)
{
    struct quic_lb_lb_ctx *context = ctx;
    return ((context == NULL) ? 0 :
            context->decrypt(ctx, cid, sid, cid_len));
}

