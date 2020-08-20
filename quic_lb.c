/*
 * Copyright (c) 2020 F5 Networks Inc.
 * This source code is subject to the terms of the Apache License,
 * version 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 */
#ifdef NOBIGIP
#include <openssl/evp.h>
#include "quic_lb.h"
#else
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
#define QUIC_LB_NONCE_MIN 8
#define QUIC_LB_NONCE_MAX 16

struct quic_lb_lb_ctx {
    UINT8            cr : 2;
    UINT8            encode_length : 1;
    enum quic_lb_alg alg : 5;
    size_t           sidl;
    int            (*decrypt)(void *ctx, void *cid, void *sid, size_t *cid_len);
    void            *crypto_ctx;
    size_t           nonce_len;
};

struct quic_lb_server_ctx {
    UINT8            cr : 2;
    UINT8            encode_length : 1;
    enum quic_lb_alg alg : 5;
    size_t           sidl;
    size_t           cidl;
    UINT8            sid[QUIC_LB_USABLE_BYTES];
    void           (*encrypt)(void *ctx, void*cid, void *server_use);
    int            (*server_use)(void *ctx, void *cid, void *buf);
    void            *crypto_ctx;
    size_t           nonce_len;
    UINT128          nonce_ctr; /* counter for nonce */
    void            *decrypt_ctx; /* Only needed for BCID server use */
};

static void
quic_lb_set_first_octet(struct quic_lb_server_ctx *ctx, UINT8 *ptr)
{
    if (ctx->encode_length) {
        *ptr = ctx->cidl - 1;
    } else {
        rndset(ptr, RND_PSEUDO, 1);
    }
    *ptr &= 0x3f;
    *ptr |= (ctx->cr << 6);
}

/* Algorithm-specific functions */
static void
quic_lb_pcid_encrypt(void *ctx, void *cid, void *server_use)
{
    struct quic_lb_server_ctx *cfg = ctx;
    UINT8 *ptr = cid;

    quic_lb_set_first_octet(cfg, ptr);
    ptr++;
    memcpy(ptr, cfg->sid, cfg->sidl);
    ptr += cfg->sidl;
    if (cfg->cidl > (cfg->sidl + 1)) {
        memcpy(ptr, server_use, cfg->cidl - (cfg->sidl + 1));
    }
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

static int
quic_lb_pcid_server_use(void *ctx, void *cid, void *buf)
{
    struct quic_lb_server_ctx *cfg = ctx;
    UINT8 *ptr = cid;

    ptr += (1 + cfg->sidl);
    memcpy(buf, ptr, cfg->cidl - cfg->sidl - 1);
    return (cfg->cidl - cfg->sidl - 1);
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
    return ERR_OTHER;
}

static void
quic_lb_scid_encrypt(void *ctx, void *cid, void *server_use)
{
    struct quic_lb_server_ctx *cfg = ctx;
    UINT8  *nonce = cid + 1, *sid = nonce + cfg->nonce_len,
           *extra = sid + cfg->sidl;

    if (cfg->nonce_ctr > ((1 << (cfg->nonce_len * 8)) - 1)) {
        /* Nonce is not big enough for unique CIDs */
        goto err;
    }
    quic_lb_set_first_octet(cfg, (UINT8 *)cid);
    memcpy(nonce, &cfg->nonce_ctr, cfg->nonce_len); /* Host order! */
    memcpy(sid, cfg->sid, cfg->sidl);
    /* 1st Pass */
    if (quic_lb_encrypt_apply_nonce(cfg->crypto_ctx, nonce, cfg->nonce_len, sid,
            cfg->sidl) != ERR_OK) {
        goto err;
    }
    cfg->nonce_ctr++;
    /* 2nd Pass */
    if (quic_lb_encrypt_apply_nonce(cfg->crypto_ctx, sid, cfg->sidl, nonce,
            cfg->nonce_len) != ERR_OK) {
        goto err;
    }
    /* 3rd Pass */
    if (quic_lb_encrypt_apply_nonce(cfg->crypto_ctx, nonce, cfg->nonce_len, sid,
            cfg->sidl) != ERR_OK) {
        goto err;
    }
    if ((UINT8 *)cid + cfg->cidl > extra) {
        memcpy(extra, server_use, cfg->cidl - (1 + cfg->nonce_len + cfg->sidl));
    }
    return;
err:
    /* Go to 5-tuple routing*/
    rndset(cid, RND_PSEUDO, cfg->cidl);
    *(UINT8 *)cid &= 0xc0;
    return;
}

static int
quic_lb_scid_decrypt(void *ctx, void *cid, void *sid, size_t *cid_len)
{
    struct quic_lb_lb_ctx *cfg = ctx;
    UINT8 nonce[cfg->nonce_len];

    if (cfg->encode_length) {
        *cid_len = (size_t)(*(UINT8 *)cid & 0x3f) + 1;
    }
    memcpy(nonce, cid + 1, cfg->nonce_len);
    memset(sid, 0, sizeof(sid));
    memcpy(sid, cid + 1 + cfg->nonce_len, cfg->sidl);
    /* 1st Pass */
    if (quic_lb_encrypt_apply_nonce(cfg->crypto_ctx, nonce, cfg->nonce_len, sid,
            cfg->sidl) != ERR_OK) {
        goto err;
    }
    /* 2nd Pass */
    if (quic_lb_encrypt_apply_nonce(cfg->crypto_ctx, sid, cfg->sidl, nonce,
            cfg->nonce_len) != ERR_OK) {
        goto err;
    }
    /* 3rd Pass */
    if (quic_lb_encrypt_apply_nonce(cfg->crypto_ctx, nonce, cfg->nonce_len, sid,
            cfg->sidl) != ERR_OK) {
        goto err;
    }
    return cfg->sidl;
err:
    return 0;
}

static int
quic_lb_scid_server_use(void *ctx, void *cid, void *server_use)
{
    struct quic_lb_server_ctx *cfg = ctx;
    int    base_len = 1 + cfg->nonce_len + cfg->sidl;
    UINT8 *source = (UINT8 *)cid + base_len;
    memcpy(server_use, source, cfg->cidl - base_len);
    return cfg->cidl - base_len;
}

static void
quic_lb_bcid_encrypt(void *ctx, void *cid, void *server_use)
{
    struct quic_lb_server_ctx *cfg = ctx;
    UINT8 *ptr = cid, *svr_use_ptr = server_use;
    UINT8 block[QUIC_LB_BLOCK_SIZE];
    int ct_len, i;

    quic_lb_set_first_octet(cfg, ptr);
    ptr++;
    memcpy(&block[0], cfg->sid, cfg->sidl);
    memcpy(&block[cfg->sidl], svr_use_ptr, sizeof(block) - cfg->sidl);
    svr_use_ptr += (sizeof(block) - cfg->sidl);
    if ((EVP_EncryptUpdate(cfg->crypto_ctx, ptr, &ct_len, block,
             sizeof(block)) != 1) || (ct_len != sizeof(block))) {
        goto err;
    }
    memcpy(ptr + sizeof(block), svr_use_ptr, cfg->cidl - 1 - sizeof(block));
    return;
err:
    /* Go to 5-tuple routing*/
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

static int
quic_lb_bcid_server_use(void *ctx, void *cid, void *buf)
{
    struct quic_lb_server_ctx *cfg = ctx;
    UINT8 *ptr = cid + 1;
    UINT8 block[QUIC_LB_BLOCK_SIZE];
    int pt_len;

    if ((EVP_DecryptUpdate(cfg->decrypt_ctx, &block[0], &pt_len, ptr,
            sizeof(block)) != 1) || (pt_len != sizeof(block))) {
        goto err;
    }
    memcpy(buf, &block[cfg->sidl], pt_len - cfg->sidl);
    memcpy((UINT8 *)buf + pt_len - cfg->sidl, ptr + pt_len, cfg->cidl -
            pt_len - 1);
    return (cfg->cidl - 1 - cfg->sidl);
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
    memset(ctx, 0, sizeof(struct quic_lb_lb_ctx));
    ctx->encode_length = encode_len;
    if (sidl == 0) {
        goto fail;
    }
    ctx->sidl = sidl;
    switch (alg) {
    case QUIC_LB_PCID:
        if (sidl > QUIC_LB_USABLE_BYTES) {
            goto fail;
        }
        ctx->decrypt = quic_lb_pcid_decrypt;
        ctx->crypto_ctx = NULL;
        break;
    case QUIC_LB_SCID:
        if ((nonce_len < QUIC_LB_NONCE_MIN) ||
                (nonce_len > QUIC_LB_NONCE_MAX)) {
            goto fail;
        }
        if (nonce_len + sidl > QUIC_LB_USABLE_BYTES) {
            goto fail;
        }
        ctx->decrypt = quic_lb_scid_decrypt;
        ctx->crypto_ctx = EVP_CIPHER_CTX_new();
        if (ctx->crypto_ctx == NULL) {
            goto fail;
        }
        if (EVP_CipherInit_ex(ctx->crypto_ctx, EVP_aes_128_ecb(), NULL, key,
                 NULL, 1) == 0) {
            goto fail;
        }
        ctx->nonce_len = nonce_len;
        break;
    case QUIC_LB_BCID:
        if (sidl > QUIC_LB_BLOCK_SIZE) {
            goto fail;
        }
        ctx->decrypt = quic_lb_bcid_decrypt;
        ctx->crypto_ctx = EVP_CIPHER_CTX_new();
        if (ctx->crypto_ctx == NULL) {
            goto fail;
        }
        if (EVP_CipherInit_ex(ctx->crypto_ctx, EVP_aes_128_ecb(), NULL, key,
                NULL, 0) == 0) {
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
        size_t sidl, UINT8 *key, size_t nonce_len, size_t server_use_len,
        UINT8 *sid)
{
    struct quic_lb_server_ctx *ctx = umalloc(sizeof(struct quic_lb_server_ctx),
            M_FILTER, UM_ZERO);

    if (ctx == NULL) {
        goto fail;
    }
    memset(ctx, 0, sizeof(struct quic_lb_server_ctx));
    if (cr > 0x2) {
        goto fail;
    }
    ctx->cr = cr;
    ctx->encode_length = encode_len;
    if (sidl == 0) {
        goto fail;
    }
    ctx->sidl = sidl;
    memcpy(ctx->sid, sid, sidl);
    switch (alg) {
    case QUIC_LB_PCID:
        ctx->cidl = 1 + sidl + server_use_len;
        if (ctx->cidl > QUIC_LB_MAX_CID_LEN) {
            goto fail;
        }
        ctx->encrypt = quic_lb_pcid_encrypt;
        ctx->server_use = quic_lb_pcid_server_use;
        break;
    case QUIC_LB_SCID:
        if ((nonce_len < QUIC_LB_NONCE_MIN) ||
                (nonce_len > QUIC_LB_NONCE_MAX)) {
            goto fail;
        }
        ctx->cidl = 1 + sidl + nonce_len + server_use_len;
        if (ctx->cidl > QUIC_LB_MAX_CID_LEN) {
            goto fail;
        }
        ctx->encrypt = quic_lb_scid_encrypt;
        ctx->server_use = quic_lb_scid_server_use;
        ctx->crypto_ctx = EVP_CIPHER_CTX_new();
        if (ctx->crypto_ctx == NULL) {
            goto fail;
        }
        /*
         * CTR mode just encrypts the nonce using AES-ECB and XORs it with
         * the plaintext or ciphertext. So for encrypt or decrypt, in this
         * case we're technically encrypting.
         */
        if (EVP_CipherInit_ex(ctx->crypto_ctx, EVP_aes_128_ecb(), NULL, key,
                 NULL, 1) == 0) {
            EVP_CIPHER_CTX_free(ctx->crypto_ctx);
            goto fail;
        }
        ctx->nonce_len = nonce_len;
        break;
    case QUIC_LB_BCID:
        if (sidl > QUIC_LB_BLOCK_SIZE) {
            goto fail;
        }
        ctx->cidl = 1 + MAX(QUIC_LB_BLOCK_SIZE, sidl + server_use_len);
        if (ctx->cidl > QUIC_LB_MAX_CID_LEN) {
            goto fail;
        }
        ctx->encrypt = quic_lb_bcid_encrypt;
        ctx->server_use = quic_lb_bcid_server_use;
        ctx->crypto_ctx = EVP_CIPHER_CTX_new();
        if (ctx->crypto_ctx == NULL) {
            goto fail;
        }
        if (EVP_CipherInit_ex(ctx->crypto_ctx, EVP_aes_128_ecb(), NULL, key,
                NULL, 1) == 0) {
            goto fail;
        }
        if (EVP_CIPHER_CTX_set_padding(ctx->crypto_ctx, 0) == 0) {
            goto fail;
        }
        ctx->decrypt_ctx = EVP_CIPHER_CTX_new();
        if (ctx->decrypt_ctx == NULL) {
            goto fail;
        }
        if (EVP_CipherInit_ex(ctx->decrypt_ctx, EVP_aes_128_ecb(), NULL, key,
                NULL, 0) == 0) {
            goto fail;
        }
        if (EVP_CIPHER_CTX_set_padding(ctx->decrypt_ctx, 0) == 0) {
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
        if (ctx->decrypt_ctx != NULL) {
            EVP_CIPHER_CTX_free(ctx->decrypt_ctx);
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
quic_lb_encrypt_cid(void *ctx, void *cid, void *server_use)
{
    struct quic_lb_server_ctx *context = ctx;

    if (context == NULL) {
        /* No config, return a 5-tuple route */
        rndset(cid, RND_PSEUDO, context->cidl);
        *(UINT8 *)cid |= QUIC_LB_TUPLE_ROUTE;
    } else {
        context->encrypt(ctx, cid, server_use);
    }
}

void
quic_lb_encrypt_cid_random(void *ctx, void *cid)
{
    struct quic_lb_server_ctx *context = ctx;
    UINT8 server_use[context->cidl];

    rndset(server_use, RND_PSEUDO, sizeof(server_use));
    context->encrypt(ctx, cid, server_use);
}

int
quic_lb_decrypt_cid(void *ctx, void *cid, void *sid, size_t *cid_len)
{
    struct quic_lb_lb_ctx *context = ctx;
    return ((context == NULL) ? 0 : context->decrypt(ctx, cid, sid, cid_len));
}

int
quic_lb_get_server_use(void *ctx, void *cid, void *buf)
{
    struct quic_lb_server_ctx *context = ctx;
    return ((context == NULL) ? 0 : context->server_use(ctx, cid, buf));
}

