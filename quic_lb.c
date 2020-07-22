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

enum quic_lb_alg {
    QUIC_LB_OCID,
    QUIC_LB_SCID,
    QUIC_LB_BCID,
};

struct quic_lb_generic_config {
    UINT8  cr : 2;
    UINT8  encode_length : 1;
    enum quic_lb_alg alg : 5;
};

struct quic_lb_ocid_config {
    UINT8            cr : 2;
    UINT8  encode_length : 1;
    enum quic_lb_alg alg : 5;
    UINT8            sidl;
    UINT8            bitmask[QUIC_LB_USABLE_BYTES];
    /* These are presented in host order */
    UINT8            modulus[QUIC_LB_OCID_SIDL_MAX];
    UINT8            divisor[QUIC_LB_OCID_SIDL_MAX];
};

struct quic_lb_scid_config {
    UINT8            cr : 2;
    UINT8  encode_length : 1;
    enum quic_lb_alg alg : 5;
    UINT8            nonce_len;
    UINT8            sidl;
    UINT8            sid[QUIC_LB_SCID_SIDL_MAX];
    UINT128          nonce_ctr;
    EVP_CIPHER_CTX  *ctx;
};

struct quic_lb_bcid_config {
    UINT8            cr : 2;
    UINT8  encode_length : 1;
    enum quic_lb_alg alg : 5;
    UINT8            zp_len;
    UINT8            sidl;
    UINT8            sid[QUIC_LB_BCID_SIDL_MAX];
    UINT8            key[16];
    EVP_CIPHER_CTX  *ctx;
};

#ifndef UINT128_MAX
   /* Get around the inability to define 128-bit constants */
   UINT64 uint128_max_array[2] = {0xffffffffffffffffULL,
           0xffffffffffffffffULL};
   #define UINT128_MAX *(UINT128 *)uint128_max_array
#endif

/*
 * Note: this is NOT deterministic because the multiple selection must always
 * be random.
 */
static void
quic_lb_ocid_encrypt(void *cid, void *config, size_t cid_len, void *server_use)
{
    struct quic_lb_ocid_config *cfg = config;
    UINT128 max_encoding, max_multiple, multiple = UINT128_MAX, encoding;
    UINT128 divisor = 0, modulus = 0;
    UINT8  *cid_ptr, mask_bits = 0, rand_bits, *mask;
    UINT8  *svr_use_ptr = server_use;
    int     i, shift, encode_shift;

    for (i = 0; i < (cid_len - 1); i++) {
        mask_bits += bit_count(cfg->bitmask[i]);
    }
    DBG_ASSERT("QUIC-LB config mismatch", cid_len >
            ROUNDUPDIV(mask_bits + 18, 8));
    max_encoding = ((UINT128)0x1 << mask_bits) - 1;
    memcpy(&divisor, cfg->divisor, sizeof(cfg->divisor));
    memcpy(&modulus, cfg->modulus, sizeof(cfg->modulus));
    max_multiple = (max_encoding / divisor);
    if (((max_multiple * divisor) + modulus) > max_encoding) {
        max_multiple--;
    }
    /*
     * Do not overweight low multiples. We must retry if the result is very
     * large.
     */
    while ((UINT128_MAX - multiple) < max_multiple) {
        rndset(&multiple, RND_PSEUDO, sizeof(multiple));
    }
    multiple = multiple % max_multiple;
    encoding = modulus + (divisor * multiple);

    /* Put the encoding in the routing mask */
    memset(cid, 0, cid_len);
    cid_ptr = (UINT8 *)cid + cid_len - 1;
    mask = (UINT8 *)cfg->bitmask + cid_len - 2;
    encode_shift = 0;
    for (i = 1; i < cid_len; i++) {
        rand_bits = *svr_use_ptr;
        svr_use_ptr++;
        for (shift = 0; shift < 8; shift++) {
            if (((*mask >> shift) & 0x1) == 0x1) {
                *cid_ptr |= (((encoding >> encode_shift) & 0x1) << shift);
                encode_shift++;
            } else {
                *cid_ptr |= (rand_bits & (0x1 << shift));
            }
        }
        cid_ptr--;
        mask--;
    }
    *cid_ptr = cfg->encode_length ? (cid_len - 1) : ((*svr_use_ptr) & 0x3f);
    *cid_ptr |= ((UINT8)cfg->cr << 6); /* Set cfg rotation bits. */
}

static err_t
quic_lb_ocid_decrypt(void *cid, void *config, size_t *cid_len, UINT8 *sid)
{
    struct quic_lb_ocid_config *cfg = config;
    UINT128 encoding = 0, divisor = 0, result;
    int     i, shift, encode_shift;
    UINT8  *cid_ptr, *mask;

    /* Get the encoding from the routing mask */
    cid_ptr = (UINT8 *)cid + sizeof(cfg->bitmask);
    mask = (UINT8 *)cfg->bitmask + sizeof(cfg->bitmask) - 1;
    encode_shift = 0;
    if (cfg->encode_length) {
        *cid_len = (*(UINT8 *)cid & 0x3f) + 1;
    }
    for (i = 0; i < sizeof(cfg->bitmask); i++) {
        if (*mask == 0) {
            goto skip_byte;
        }
        for (shift = 0; shift < 8; shift++) {
            if (((*mask >> shift) & 0x1) == 0x1) {
                encoding |= ((UINT128)((*cid_ptr >> shift) & 0x1) <<
                        encode_shift);
                encode_shift++;
            }
        }
skip_byte:
        cid_ptr--;
        mask--;
    }
    memcpy(&divisor, cfg->divisor, sizeof(cfg->divisor));
    result = encoding % divisor;
    memcpy(sid, &result, cfg->sidl);
    return ERR_OK;
}

#if 0
static void
quic_lb_scid_encrypt(void *cid, void *config, size_t cid_len, void *server_use)
{
    struct quic_lb_scid_config *cfg = config;
    UINT8 *ptr = cid, *svr_use_ptr = server_use;
    UINT8  nonce[16];
    UINT8  ct[16];
    int    ct_len, i;

    *ptr = (cfg->cr << 6) | (cfg->encode_length ? (cid_len - 1) :
            ((*svr_use_ptr) & 0x3f));
    ptr++;
    memcpy(ptr, svr_use_ptr, cfg->nonce_len);
    memset(nonce, 0, sizeof(nonce));
    memcpy(nonce, ptr, cfg->nonce_len);
    ptr += cfg->nonce_len;
    if (EVP_EncryptUpdate(cfg->ctx, ct, &ct_len, nonce, sizeof(nonce)) !=
            1) {
        goto err;
    }
    if (ct_len != sizeof(nonce)) {
        goto err;
    }
    for (i = 0; i < cfg->sidl; i++) {
        *(ptr + i) = ct[i] ^ cfg->sid[i];
    }
    return;
err:
    /* Go to 5-tuple routing*/
    *(UINT8 *)cid &= 0xc0;
    return;
}

static UINT64
quic_lb_scid_decrypt(void *cid, void *config, size_t *cid_len)
{
    struct quic_lb_scid_config *cfg = config;
    UINT8 *ptr = cid;
    UINT8  nonce[16], ct[16], sid[11];
    int    ct_len, i;

    if (cfg->encode_length) {
        *cid_len = ((*ptr) & 0x3f) + 1;
    }
    ptr++;
    memset(nonce, 0, sizeof(nonce));
    memcpy(nonce, ptr, cfg->nonce_len);
    ptr += cfg->nonce_len;
    if (EVP_EncryptUpdate(cfg->ctx, ct, &ct_len, nonce, sizeof(nonce)) !=
            1) {
        goto err;
    }
    if (ct_len != sizeof(nonce)) {
        goto err;
    }
    memset(sid, 0, sizeof(sid));
    for (i = 0; i < cfg->sidl; i++) {
        sid[i] = *(ptr + i) ^ ct[i];
    }
    return (*(UINT64 *)sid);
err:
    return 0;
}
#endif // old

static inline err_t
quic_lb_encrypt_apply_nonce(struct quic_lb_scid_config *cfg, UINT8 *nonce,
        UINT8 nonce_len, UINT8 *target, UINT8 target_len)
{
    UINT8 pt[16];
    UINT8 ct[16];
    int ct_len, i;

    memset(pt, 0, sizeof(pt));
    memcpy(pt, nonce, nonce_len);
    if (EVP_EncryptUpdate(cfg->ctx, ct, &ct_len, pt, sizeof(pt)) !=
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
quic_lb_scid_encrypt(void *cid, void *config, size_t cid_len, void *server_use)
{
    struct quic_lb_scid_config *cfg = config;
    UINT8  *nonce = cid + 1, *sid = nonce + cfg->nonce_len,
           *extra = sid + cfg->sidl, *svr_use_ptr = server_use;

    if (cfg->nonce_ctr > ((1 << (cfg->nonce_len * 8)) - 1)) {
        /* Nonce is not big enough for unique CIDs */
        goto err;
    }
    if (cfg->encode_length) {
        *(UINT8 *)cid = cid_len - 1;
    } else {
        memcpy(cid, server_use, 1);
    }
    *(UINT8 *)cid &= 0x3f;
    *(UINT8 *)cid |= (cfg->cr << 6);
    svr_use_ptr++;
    memcpy(nonce, &cfg->nonce_ctr, cfg->nonce_len); /* Host order! */
    memcpy(sid, cfg->sid, cfg->sidl);
    /* 1st Pass */
    if (quic_lb_encrypt_apply_nonce(cfg, nonce, cfg->nonce_len, sid,
            cfg->sidl) != ERR_OK) {
        goto err;
    }
    cfg->nonce_ctr++;
    /* 2nd Pass */
    if (quic_lb_encrypt_apply_nonce(cfg, sid, cfg->sidl, nonce,
            cfg->nonce_len) != ERR_OK) {
        goto err;
    }
    /* 3rd Pass */
    if (quic_lb_encrypt_apply_nonce(cfg, nonce, cfg->nonce_len, sid,
            cfg->sidl) != ERR_OK) {
        goto err;
    }
    if ((UINT8 *)cid + cid_len > extra) {
        memcpy(extra, server_use + 1, cid_len -
                (1 + cfg->nonce_len + cfg->sidl));
    }
    return;
err:
    /* Go to 5-tuple routing*/
    rndset(cid, RND_PSEUDO, cid_len);
    *(UINT8 *)cid &= 0xc0;
    return;
}

static err_t
quic_lb_scid_decrypt(void *cid, void *config, size_t *cid_len, UINT8 *sid)
{
    struct quic_lb_scid_config *cfg = config;
    UINT8 nonce[cfg->nonce_len];

    if (cfg->encode_length) {
        *cid_len = (*(UINT8 *)cid & 0x3f) + 1;
    }
    memcpy(nonce, cid + 1, cfg->nonce_len);
    memset(sid, 0, sizeof(sid));
    memcpy(sid, cid + 1 + cfg->nonce_len, cfg->sidl);
    /* 1st Pass */
    if (quic_lb_encrypt_apply_nonce(cfg, nonce, cfg->nonce_len, sid,
            cfg->sidl) != ERR_OK) {
        goto err;
    }
    /* 2nd Pass */
    if (quic_lb_encrypt_apply_nonce(cfg, sid, cfg->sidl, nonce,
            cfg->nonce_len) != ERR_OK) {
        goto err;
    }
    /* 3rd Pass */
    if (quic_lb_encrypt_apply_nonce(cfg, nonce, cfg->nonce_len, sid,
            cfg->sidl) != ERR_OK) {
        goto err;
    }
    return ERR_OK;
err:
    return ERR_OTHER;
}

static void
quic_lb_bcid_encrypt(void *cid, void *config, size_t cid_len, void *server_use)
{
    struct quic_lb_bcid_config *cfg = config;
    UINT8 *ptr = cid, *svr_use_ptr = server_use;
    UINT8 block[16];
    int ct_len, i;

    *ptr = (cfg->cr << 6) | (cfg->encode_length ? (cid_len - 1) :
            ((*svr_use_ptr) & 0x3f));
    memcpy(&block[0], cfg->sid, cfg->sidl);
    memset(&block[cfg->sidl], 0, cfg->zp_len);
    svr_use_ptr++;
    for (i = cfg->sidl + cfg->zp_len; i < sizeof(block); i++) {
       block[i] = *svr_use_ptr;
       svr_use_ptr++;
    }
    if ((EVP_EncryptUpdate(cfg->ctx, ptr + 1, &ct_len, block, sizeof(block))
            != 1) || (ct_len != sizeof(block))) {
        goto err;
    }

    for (i = ct_len + 1; i < cid_len; i++) {
        *(ptr + i) = *svr_use_ptr;
        svr_use_ptr++;
    }
    return;
err:
    /* Go to 5-tuple routing*/
    *(UINT8 *)cid &= 0xc0;
    return;
}

static err_t
quic_lb_bcid_decrypt(void *cid, void *config, size_t *cid_len, UINT8 *sid)
{
    struct quic_lb_bcid_config *cfg = config;
    UINT8 *ptr = cid;
    UINT8 block[16];
    UINT8 zeroes[cfg->zp_len];
    int pt_len;

    if (cfg->encode_length) {
        *cid_len = (*(UINT8 *)cid & 0x3f) + 1;
    }
    memset(block, 0, sizeof(block)); // mhd;
    if ((EVP_DecryptUpdate(cfg->ctx, &block[0], &pt_len, ptr + 1,
            sizeof(block)) != 1) || (pt_len != sizeof(block))) {
        goto err;
    }
    memcpy(sid, block, cfg->sidl);
    memset(zeroes, 0, sizeof(zeroes));
    if (memcmp(&block[cfg->sidl], zeroes, cfg->zp_len) != 0) {
        goto err;
    }
    return ERR_OK;
err:
    return ERR_OTHER;
}

/* server_use MUST be of length cid_len */
void
quic_lb_encrypt_cid(void *cid, void *config, size_t cid_len, void *server_use)
{
    struct quic_lb_generic_config *generic;

    if (config == NULL) {
        rndset(cid, RND_PSEUDO, cid_len);
        *(UINT8 *)cid |= QUIC_LB_TUPLE_ROUTE;
        goto out;
    }
    generic = (struct quic_lb_generic_config *)config;
    switch(generic->alg) {
    case QUIC_LB_OCID:
        quic_lb_ocid_encrypt(cid, config, cid_len, server_use);
        break;
    case QUIC_LB_SCID:
        quic_lb_scid_encrypt(cid, config, cid_len, server_use);
        break;
    case QUIC_LB_BCID:
        quic_lb_bcid_encrypt(cid, config, cid_len, server_use);
        break;
    }
out:
    return;
}

void
quic_lb_encrypt_cid_random(void *cid, void *config, size_t cid_len)
{
    UINT8 server_use[cid_len];

    rndset(server_use, RND_PSEUDO, sizeof(server_use));
    quic_lb_encrypt_cid(cid, config, cid_len, server_use);
}

err_t
quic_lb_decrypt_cid(void *cid, void *config, size_t *cid_len, void *sid)
{
    struct quic_lb_generic_config *generic;
    err_t  err = ERR_OTHER;

    generic = (struct quic_lb_generic_config *)config;
    switch(generic->alg) {
    case QUIC_LB_OCID:
        err = quic_lb_ocid_decrypt(cid, config, cid_len, sid);
        break;
    case QUIC_LB_SCID:
        err = quic_lb_scid_decrypt(cid, config, cid_len, sid);
        break;
    case QUIC_LB_BCID:
        err = quic_lb_bcid_decrypt(cid, config, cid_len, sid);
        break;
    }
    return err;
}

/* The bitmask should be filled out for the entire 19 byte length */
void *
quic_lb_load_ocid_config(UINT8 cr, BOOL encode_len, UINT8 *bitmask,
        UINT8 *modulus, UINT8 *divisor, UINT8 sidl)
{
    struct quic_lb_ocid_config *cfg = umalloc(
            sizeof(struct quic_lb_ocid_config), M_FILTER, UM_ZERO);

    if (cfg == NULL) {
        goto out;
    }
    if (cr > 0x3) {
        ufree(cfg);
        cfg = NULL;
        goto out;
    }
    cfg->cr = cr;
    cfg->encode_length = encode_len;
    cfg->alg = QUIC_LB_OCID;
    cfg->sidl = sidl;
    memcpy(cfg->bitmask, bitmask, QUIC_LB_USABLE_BYTES);
    memcpy(cfg->modulus, modulus, QUIC_LB_OCID_SIDL_MAX);
    memcpy(cfg->divisor, divisor, QUIC_LB_OCID_SIDL_MAX);

out:
    return cfg;
}

void *
quic_lb_load_scid_config(UINT8 cr, BOOL encode_len, UINT8 *key, UINT8 sidl,
        UINT8 nonce_len, UINT8 *sid)
{
    struct quic_lb_scid_config *cfg = umalloc(
            sizeof(struct quic_lb_scid_config), M_FILTER, UM_ZERO);

    if (cfg == NULL) {
        goto out;
    }
    if ((cr > 0x3) || (nonce_len < 8) || (nonce_len > 16) ||
            (nonce_len + sidl > QUIC_LB_USABLE_BYTES)) {
        ufree(cfg);
        cfg = NULL;
        goto out;
    }
    cfg->cr = cr;
    cfg->encode_length = encode_len;
    cfg->alg = QUIC_LB_SCID;
    cfg->nonce_len = nonce_len;
    cfg->sidl = sidl;
    memcpy(cfg->sid, sid, sidl);
    cfg->nonce_ctr = 0;
    cfg->ctx = EVP_CIPHER_CTX_new();
    /*
     * CTR mode just encrypts the nonce using AES-ECB and XORs it with
     * the plaintext or ciphertext. So for encrypt or decrypt, in this
     * case we're technically encrypting.
     */
    if (cfg->ctx == NULL) {
        ufree(cfg);
        cfg = NULL;
        goto out;
    }
    if (EVP_CipherInit_ex(cfg->ctx, EVP_aes_128_ecb(), NULL, key, NULL, 1)
            == 0) {
        EVP_CIPHER_CTX_free(cfg->ctx);
        ufree(cfg);
        cfg = NULL;
    }
out:
    return cfg;
}

void *
quic_lb_load_bcid_config(UINT8 cr, BOOL encode_len, UINT8 *key, UINT8 sidl,
        UINT8 zp_len, UINT8 *sid, BOOL encrypt)
{
    struct quic_lb_bcid_config *cfg = umalloc(
            sizeof(struct quic_lb_bcid_config), M_FILTER, UM_ZERO);

    if (cfg == NULL) {
        goto out;
    }
    cfg->ctx = NULL;
    if ((cr > 0x3) || (zp_len < 4) || (zp_len + sidl > 12)) {
        goto fail;
    }
    cfg->cr = cr;
    cfg->encode_length = encode_len;
    cfg->alg = QUIC_LB_BCID;
    cfg->zp_len = zp_len;
    cfg->sidl = sidl;
    memcpy(cfg->sid, sid, sidl);
    memcpy(cfg->key, key, sizeof(cfg->key));
    cfg->ctx = EVP_CIPHER_CTX_new();
    if (cfg->ctx == NULL) {
        goto fail;
    }
    if (EVP_CipherInit_ex(cfg->ctx, EVP_aes_128_ecb(), NULL, key, NULL,
            encrypt ? 1 : 0) == 0) {
        goto fail;
    }
    if (EVP_CIPHER_CTX_set_padding(cfg->ctx, 0) == 0) {
        goto fail;
    }
out:
    return cfg;
fail:
    if (cfg->ctx != NULL) {
        EVP_CIPHER_CTX_free(cfg->ctx);
    }
    ufree(cfg);
    return NULL;
}

void
quic_lb_free_config(void *config)
{
    struct quic_lb_generic_config *generic;
    EVP_CIPHER_CTX  *ctx;

    generic = (struct quic_lb_generic_config *)config;
    switch(generic->alg) {
    case QUIC_LB_OCID:
        ctx = NULL;
        goto out;
    case QUIC_LB_SCID:
        ctx = ((struct quic_lb_scid_config *)config)->ctx;
        break;
    case QUIC_LB_BCID:
        ctx = ((struct quic_lb_bcid_config *)config)->ctx;
        break;
    }
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
out:
    return;
}
