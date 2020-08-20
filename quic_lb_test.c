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
#define TEST_QUIC_LB_PER_SERVER 1
#define TEST_QUIC_LB_BLOCK_SIZE 16

#define TEST_QUIC_KEY_SIZE 16

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
test_quic_lb_alg(enum quic_lb_alg alg)
{
    UINT8  sid[QUIC_LB_MAX_CID_LEN], cid[QUIC_LB_MAX_CID_LEN];
    UINT8  result[QUIC_LB_MAX_CID_LEN], nonce[QUIC_LB_MAX_CID_LEN];
    UINT8  key[TEST_QUIC_KEY_SIZE], server_use[QUIC_LB_MAX_CID_LEN];
    int    cfg, srv, run, i;
    size_t cid_len, cidl, svr_use_len, nonce_len, sul, sidl = 0;
    BOOL   len_encode;
    void  *lb_ctx, *server_ctx;

    for (cfg = 0; cfg < TEST_QUIC_LB_NUM_CONFIG; cfg++) {
        len_encode = (cfg % 2 == 0);
        sidl++;
        /* These are not used by all algorithms, but are harmless to set. */
        rndset(key, RND_PSEUDO, sizeof(key));
        nonce_len = rnd8_range(RND_PSEUDO, 8) + 8;
        while ((nonce_len + sidl + 1) > QUIC_LB_MAX_CID_LEN) {
            nonce_len--;
        }
#ifdef NOBIGIP
        switch(alg) {
        case QUIC_LB_PCID:
            printf("PCID LB configuration: cr_bits 0x0 length_self_encoding: %s"
                    " sid_len %zu\n", len_encode ? "y" : "n", sidl);
            break;
        case QUIC_LB_SCID:
            printf("SCID LB configuration: cr_bits 0x0 length_self_encoding: %s"
                    " nonce_len %zu sid_len %zu ", len_encode ? "y" : "n",
                    nonce_len, sidl);
            printf("key ");
            test_quic_print_buffer(key, TEST_QUIC_KEY_SIZE);
            printf("\n");
            break;
        case QUIC_LB_BCID:
            printf("BCID LB configuration: cr_bits 0x0 length_self_encoding: %s"
                    " sid_len %zu ", len_encode ? "y" : "n", sidl);
            printf("key ");
            test_quic_print_buffer(key, TEST_QUIC_KEY_SIZE);
            printf("\n");
            break;
        }
#endif
        lb_ctx = quic_lb_lb_ctx_init(alg, len_encode, sidl, key, nonce_len);
        CUT_ASSERT(lb_ctx != NULL);
        for (srv = 0; srv < TEST_QUIC_LB_NUM_SRV_ID; srv++) {
            rndset(sid, RND_PSEUDO, sidl);
            server_ctx = NULL;
            svr_use_len = (alg == QUIC_LB_BCID) ?
                    (TEST_QUIC_LB_BLOCK_SIZE - sidl) : srv;
            svr_use_len++;
            while (server_ctx == NULL) {
                CUT_ASSERT(svr_use_len > 0); /* do not wraparound */
                svr_use_len--;
                server_ctx = quic_lb_server_ctx_init(alg, 0x0, len_encode, sidl,
                    key, nonce_len, svr_use_len, sid);
            }
            switch (alg) {
            case QUIC_LB_PCID:
                cid_len = 1 + sidl + svr_use_len;
                break;
            case QUIC_LB_SCID:
                cid_len = 1 + nonce_len + sidl + svr_use_len;
                break;
            case QUIC_LB_BCID:
                cid_len = 1 + MAX(TEST_QUIC_KEY_SIZE, sidl + svr_use_len);
                break;
            }
            for (run = 0; run < TEST_QUIC_LB_PER_SERVER; run++) {
                rndset(server_use, RND_PSEUDO, svr_use_len);
                quic_lb_encrypt_cid(server_ctx, cid, server_use);
                CUT_ASSERT(quic_lb_decrypt_cid(lb_ctx, cid, result, &cidl) ==
                        sidl);
                CUT_ASSERT(!len_encode || (cidl == cid_len));
#ifdef NOBIGIP
                printf("cid ");
                test_quic_print_buffer(cid, cid_len);
                printf(" sid ");
                test_quic_print_buffer(sid, sidl);
                printf(" server use ");
                test_quic_print_buffer(server_use, svr_use_len);
                printf("\n");
#endif
                CUT_ASSERT(memcmp(result, sid, sidl) == 0);
                /* check server use bytes */
                sul = quic_lb_get_server_use(server_ctx, cid, result);
                /*
                 * BCID may return more bytes than configured because of the
                 * min size.
                 */
                CUT_ASSERT((alg == QUIC_LB_BCID) || (sul == svr_use_len));
                CUT_ASSERT(memcmp(result, server_use, svr_use_len) == 0);
            }
            quic_lb_server_ctx_free(server_ctx);
        }
        quic_lb_lb_ctx_free(lb_ctx);
    }
}

#ifdef NOBIGIP
int main(int argc, char* argv[])
#else
static void
test_quic_lb(void)
#endif
{
    test_quic_lb_alg(QUIC_LB_PCID);
    test_quic_lb_alg(QUIC_LB_SCID);
    test_quic_lb_alg(QUIC_LB_BCID);
}

#ifndef NOBIGIP
CUT_SUITE(quic_lb);
CUT_SUITE_TEST(quic_lb, test_quic_lb);
#endif
