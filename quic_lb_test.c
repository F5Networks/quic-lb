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

static void
test_quic_lb_pcid(void)
{
    UINT8  sidl = 0, sid[QUIC_LB_PCID_SIDL_MAX], cid[QUIC_LB_MAX_CID_LEN];
    UINT8  result[QUIC_LB_PCID_SIDL_MAX];
    int    cfg, srv, run, i;
    size_t cid_len;
    void  *record;
    BOOL   len_encode;

    for (cfg = 0; cfg < TEST_QUIC_LB_NUM_CONFIG; cfg++) {
        len_encode = (cfg % 2 == 0);
        sidl++;
        cid_len = sidl + 1;
#ifdef NOBIGIP
        printf("PCID LB configuration: cr_bits 0x0 length_self_encoding: %s "
                "sid_len %u\n", len_encode ? "y" : "n", sidl);
#endif
        for (srv = 0; srv < TEST_QUIC_LB_NUM_SRV_ID; srv++) {
            memset(sid, 0, sizeof(sid));
            rndset(sid, RND_PSEUDO, sidl);
            record = quic_lb_load_pcid_config(0, len_encode, sidl, sid);
            CUT_ASSERT(record != NULL);
            for (run = 0; run < TEST_QUIC_LB_PER_SERVER; run++) {
                quic_lb_encrypt_cid_random(cid, record, cid_len);
                CUT_ASSERT(quic_lb_decrypt_cid(cid, record, &cid_len, result) ==
                        ERR_OK);
#ifdef NOBIGIP
                printf("cid ");
                for (i = 0; i < cid_len; i++) {
                    printf("%02x", cid[i]);
                }
                printf(" sid ");
                for (i = 0; i < sidl; i++) {
                    printf("%02x", sid[i]);
                }
                printf("\n");
#endif
                CUT_ASSERT(memcmp(result, sid, sidl) == 0);
                CUT_ASSERT(cid_len == sidl + 1);
            }
            quic_lb_free_config(record);
            ufree(record);
        }
    }
}

static void
test_quic_lb_scid(void)
{
    UINT8  key[16], nonce_len, sidl = 0, sid[QUIC_LB_SCID_SIDL_MAX],
             cid[QUIC_LB_MAX_CID_LEN];
    UINT8  result[QUIC_LB_SCID_SIDL_MAX];
    int    cfg, srv, run, i;
    size_t cid_len;
    void  *record;
    BOOL   len_encode;

    for (cfg = 0; cfg < TEST_QUIC_LB_NUM_CONFIG; cfg++) {
        rndset(key, RND_PSEUDO, sizeof(key));
        len_encode = (cfg % 2 == 0);
        sidl++;
        nonce_len = rnd8_range(RND_PSEUDO, 10 - sidl) + 8;
        cid_len = sidl + nonce_len + 1;
#ifdef NOBIGIP
        printf("SCID LB configuration: cr_bits 0x0 length_self_encoding: %s "
                "nonce_len %u sid_len %u ", len_encode ? "y" : "n", nonce_len,
                sidl);
        printf("key ");
        for (i = 0; i < 16; i++) {
            printf("%02x", key[i]);
        }
        printf("\n");
#endif
        for (srv = 0; srv < TEST_QUIC_LB_NUM_SRV_ID; srv++) {
            memset(sid, 0, sizeof(sid));
            rndset(sid, RND_PSEUDO, sidl);
            record = quic_lb_load_scid_config(0, len_encode, key, sidl,
                    nonce_len, sid);
            CUT_ASSERT(record != NULL);
            for (run = 0; run < TEST_QUIC_LB_PER_SERVER; run++) {
                quic_lb_encrypt_cid_random(cid, record, cid_len);
                CUT_ASSERT(quic_lb_decrypt_cid(cid, record, &cid_len, result) ==
                        ERR_OK);
#ifdef NOBIGIP
                printf("cid ");
                for (i = 0; i < cid_len; i++) {
                    printf("%02x", cid[i]);
                }
                printf(" sid ");
                for (i = 0; i < sidl; i++) {
                    printf("%02x", sid[i]);
                }
                printf("\n");
#endif
                CUT_ASSERT(memcmp(result, sid, sidl) == 0);
                CUT_ASSERT(cid_len == sidl + nonce_len + 1);
            }
            quic_lb_free_config(record);
            ufree(record);
        }
    }
}

static void
test_quic_lb_bcid(void)
{
    UINT8  key[16], sidl = 0, sid[8], cid[QUIC_LB_MAX_CID_LEN];
    UINT8  result[QUIC_LB_BCID_SIDL_MAX];
    int    cfg, srv, run, i;
    void  *svr_cfg, *lb_cfg;
    size_t cid_len = QUIC_LB_MAX_CID_LEN, zp_len;
    BOOL   len_encode;

    for (cfg = 0; cfg < TEST_QUIC_LB_NUM_CONFIG; cfg++) {
        rndset(key, RND_PSEUDO, sizeof(key));
        len_encode = (cfg % 2 == 0);
        sidl++;
        zp_len = 12 - sidl;
#ifdef NOBIGIP
        printf("BCID LB configuration: cr_bits 0x0 length_self_encoding: %s "
                "sid_len %u zp_len %lu ", len_encode ? "y" : "n", sidl, zp_len);
        printf("key ");
        for (i = 0; i < 16; i++) {
            printf("%02x", key[i]);
        }
        printf("\n");
#endif
        for (srv = 0; srv < TEST_QUIC_LB_NUM_SRV_ID; srv++) {
            memset(sid, 0, sizeof(sid));
            rndset(sid, RND_PSEUDO, sidl);
            svr_cfg = quic_lb_load_bcid_config(0, len_encode, key, sidl, zp_len,
                    sid, TRUE);
            lb_cfg = quic_lb_load_bcid_config(0, len_encode, key, sidl, zp_len,
                    sid, FALSE);
            CUT_ASSERT(svr_cfg != NULL);
            CUT_ASSERT(lb_cfg != NULL);
            for (run = 0; run < TEST_QUIC_LB_PER_SERVER; run++) {
                quic_lb_encrypt_cid_random(cid, svr_cfg, cid_len);
                CUT_ASSERT(quic_lb_decrypt_cid(cid, lb_cfg, &cid_len, result) ==
                        ERR_OK);
#ifdef NOBIGIP
                printf("cid: ");
                for (i = 0; i < QUIC_LB_MAX_CID_LEN; i++) {
                    printf("%02x", cid[i]);
                }
                printf(" sid: ");
                for (i = 0; i < sidl; i++) {
                    printf("%02x", sid[i]);
                }
                printf("\n");
#endif
                CUT_ASSERT(memcmp(&result, sid, sidl) == 0);
                CUT_ASSERT(cid_len == QUIC_LB_MAX_CID_LEN);
            }
            quic_lb_free_config(svr_cfg);
            quic_lb_free_config(lb_cfg);
            ufree(svr_cfg);
            ufree(lb_cfg);
        }
    }
}

#ifdef NOBIGIP
int main(int argc, char* argv[])
{
    test_quic_lb_pcid();
    test_quic_lb_scid();
    test_quic_lb_bcid();
}
#else
CUT_SUITE(quic_lb);
CUT_SUITE_TEST(quic_lb, test_quic_lb_pcid);
CUT_SUITE_TEST(quic_lb, test_quic_lb_scid);
CUT_SUITE_TEST(quic_lb, test_quic_lb_bcid);
#endif
