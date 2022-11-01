/*
 * Copyright (c) 2020 F5 Networks Inc.
 * This source code is subject to the terms of the Apache License,
 * version 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 */

#ifdef NOBIGIP
#include <openssl/evp.h>
#include "quic_lb.h"
#else
#include <local/sys/types.h>
#include <local/sys/cpu.h>
#include <local/sys/err.h>
#include <local/sys/lib.h>
#include <local/sys/rnd.h>
#include <local/sys/umem.h>
#include <local/modules/hudfilter/quic/quic_lb.h>
#include <cut/cut.h>
#endif

#define TEST_QUIC_LB_NUM_CONFIG 5
#define TEST_QUIC_LB_NUM_SRV_ID 5
#define TEST_QUIC_LB_PER_SERVER 3
#define TEST_QUIC_LB_BLOCK_SIZE 16

#define TEST_QUIC_KEY_SIZE 16

// Forward declare, test-only code
void test_quic_lb_truncate();

#ifdef NOBIGIP
static void
test_quic_print_buffer(void *buf, size_t len)
{
   int i;
   UINT8 *ptr = buf;
    for (i = 0; i < len; i++) {
        printf("%02x", *ptr);
        ptr++;
    }
}
#endif /* NOBIGIP */

static void
test_quic_lb_alg()
{
    UINT8  sid[QUIC_LB_MAX_CID_LEN], cid[QUIC_LB_MAX_CID_LEN];
    UINT8  result[QUIC_LB_MAX_CID_LEN], key[TEST_QUIC_KEY_SIZE];
    int    cfg, srv, run;
    size_t cid_len, cidl, nonce_len, sidl = 0;
    BOOL   len_encode;
    void  *lb_ctx, *server_ctx;

    for (cfg = 0; cfg < TEST_QUIC_LB_NUM_CONFIG; cfg++) {
        len_encode = (cfg % 2 == 0);
        sidl++;
        /* These are not used by all algorithms, but are harmless to set. */
        rndset(key, RND_PSEUDO, sizeof(key));
        nonce_len = rnd8_range(RND_PSEUDO, 6) + 4;
        while ((nonce_len + sidl + 1) > QUIC_LB_MAX_CID_LEN) {
            nonce_len--;
        }
#ifdef NOBIGIP
        printf(" LB configuration: cr_bits 0x0 length_self_encoding: %s"
                " sid_len %zu nonce_len %zu ", len_encode ? "y" : "n",
                nonce_len, sidl);
        printf("key ");
        test_quic_print_buffer(key, TEST_QUIC_KEY_SIZE);
        printf("\n");
#endif
        lb_ctx = quic_lb_lb_ctx_init(len_encode, sidl, key, nonce_len);
        CUT_ASSERT(lb_ctx != NULL);
        for (srv = 0; srv < TEST_QUIC_LB_NUM_SRV_ID; srv++) {
            rndset(sid, RND_PSEUDO, sidl);
            server_ctx = quic_lb_server_ctx_init(0x0, len_encode, sidl,
                    key, nonce_len, sid);
            CUT_ASSERT(server_ctx != NULL);
            cid_len = sidl + nonce_len + 1;
            for (run = 0; run < TEST_QUIC_LB_PER_SERVER; run++) {
                quic_lb_encrypt_cid(server_ctx, cid);
                CUT_ASSERT(quic_lb_decrypt_cid(lb_ctx, cid, result, &cidl) ==
                        sidl);
#ifdef NOBIGIP
                printf("nonce ");
                printf("%u", run);
                printf(" cid ");
                test_quic_print_buffer(cid, cid_len);
                printf(" sid ");
                test_quic_print_buffer(sid, sidl);
                printf("\n");
#endif
                CUT_ASSERT(!len_encode || (cidl == cid_len));
                CUT_ASSERT(memcmp(result, sid, sidl) == 0);
            }
            quic_lb_server_ctx_free(server_ctx);
        }
        quic_lb_lb_ctx_free(lb_ctx);
    }
}

static void
test_quic_lb_encrypted_test_vectors() {
    UINT8 key[TEST_QUIC_KEY_SIZE] = {
        0x8f, 0x95, 0xf0, 0x92, 0x45, 0x76, 0x5f, 0x80,
        0x25, 0x69, 0x34, 0xe5, 0x0c, 0x66, 0x20, 0x7f,
    };
    UINT8 sid[] = { 0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f, 0x5f,
                    0xab, 0x65 };
    UINT8 cid1[] = { 0x07, 0x41, 0x26, 0xee, 0x38, 0xbf, 0x54, 0x54 };
    UINT8 cid2[] = { 0x4f, 0xcd, 0x3f, 0x57, 0x2d, 0x4e, 0xef, 0xb0,
                     0x46, 0xfd, 0xb5, 0x1d, 0x16, 0x4e, 0xfc, 0xcc };
    UINT8 cid3[] = { 0x90, 0x4d, 0xd2, 0xd0, 0x5a, 0x7b, 0x0d, 0xe9,
                     0xb2, 0xb9, 0x90, 0x7a, 0xfb, 0x5e, 0xcf, 0x8c,
                     0xc3 };
    UINT8 cid4[] = { 0x12, 0x12, 0x4d, 0x1e, 0xb8, 0xfb, 0xb2, 0x1e,
                     0x4a, 0x49, 0x0c, 0xa5, 0x3c, 0xfe, 0x21, 0xd0,
                     0x4a, 0xe6, 0x3a };
    UINT8 result[10];
    void *ctx;
    size_t len;
    ctx = quic_lb_lb_ctx_init(TRUE, 3, key, 4);
    quic_lb_decrypt_cid(ctx, cid1, result, &len);
    CUT_ASSERT(memcmp(sid, result, 3) == 0);
    quic_lb_lb_ctx_free(ctx);

    ctx = quic_lb_lb_ctx_init(TRUE, 10, key, 5);
    quic_lb_decrypt_cid(ctx, cid2, result, &len);
    CUT_ASSERT(memcmp(sid, result, 10) == 0);
    quic_lb_lb_ctx_free(ctx);
    
    ctx = quic_lb_lb_ctx_init(TRUE, 8, key, 8);
    quic_lb_decrypt_cid(ctx, cid3, result, &len);
    CUT_ASSERT(memcmp(sid, result, 8) == 0);
    quic_lb_lb_ctx_free(ctx);
    
    ctx = quic_lb_lb_ctx_init(TRUE, 9, key, 9);
    quic_lb_decrypt_cid(ctx, cid4, result, &len);
    CUT_ASSERT(memcmp(sid, result, 9) == 0);
    quic_lb_lb_ctx_free(ctx);

}

#ifdef NOBIGIP
int main(int argc, char* argv[])
#else
static void
test_quic_lb(void)
#endif
{
    test_quic_lb_alg();
    test_quic_lb_truncate();
    test_quic_lb_encrypted_test_vectors();
}

#ifndef NOBIGIP
CUT_SUITE(quic_lb);
CUT_SUITE_TEST(quic_lb, test_quic_lb);
#endif
