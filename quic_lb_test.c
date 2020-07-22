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
test_quic_lb_ocid(void)
{
    UINT8  bitmask[QUIC_LB_MAX_CID_LEN - 1], cid[QUIC_LB_MAX_CID_LEN],
            one_count, zero_count;
    UINT8  divisor[QUIC_LB_OCID_SIDL_MAX], modulus[QUIC_LB_OCID_SIDL_MAX],
            result[QUIC_LB_OCID_SIDL_MAX];
    BOOL   len_encode;
    size_t mask_len, cid_len;
    const UINT8 sidl = 2;
    int    cfg, srv, run, i;
    void  *record;

    for (cfg = 0; cfg < TEST_QUIC_LB_NUM_CONFIG; cfg++) {
        mask_len = rnd8_range(RND_PSEUDO, 9) + 10;
        cid_len = mask_len + 1;
try_again:
        one_count = 0;
        len_encode = (cfg % 2 == 0);
        memset(bitmask, 0, sizeof(bitmask));
        rndset(bitmask, RND_PSEUDO, mask_len);
        for (i = 0; i < mask_len; i++) {
            one_count +=  bit_count((UINT32)bitmask[i]);
        }
        zero_count = (8 * mask_len) - one_count;
        if (zero_count < 16) {
            goto try_again;
        }
        if (one_count < 32) {
            goto try_again;
        }
        memset(divisor, 0, sizeof(divisor));
        while (divisor[sidl] == 0) {
            /* Divisor had better be larger than all SIDs! */
            rndset(&divisor, RND_PSEUDO, sidl + 1);
        }
        divisor[0] |= 0x1; /* always odd */
#ifdef NOBIGIP
        printf("OCID LB configuration: cr_bits 0x0 length_self_encoding: %s "
                "bitmask ", len_encode ? "y" : "n");
        for (i = 0; i < mask_len; i++) {
            printf("%02x", bitmask[i]);
        }
        printf(" divisor ");
        for (i = 0; i < sidl + 1; i++) {
            printf("%02x", divisor[i]);
        }
        printf(" cid_len %lu\n", cid_len);
#endif
        memset(modulus, 0, sizeof(modulus));
        for (srv = 0; srv < TEST_QUIC_LB_NUM_SRV_ID; srv++) {
            rndset(modulus, RND_PSEUDO, sidl);
            record = quic_lb_load_ocid_config(0, len_encode, bitmask, modulus,
                    divisor, sidl);
            CUT_ASSERT(record != NULL);
            for (run = 0; run < TEST_QUIC_LB_PER_SERVER; run++) {
                quic_lb_encrypt_cid_random(cid, record, cid_len);
#ifdef NOBIGIP
                printf("cid ");
                for (i = 0; i < (mask_len + 1); i++) {
                    printf("%02x", cid[i]);
                }
                printf("sid ");
                for (i = 0; i < sidl; i++) {
                    printf("%02x", modulus[i]);
                }
                printf("\n");
#endif
                CUT_ASSERT(quic_lb_decrypt_cid(cid, record, &cid_len, result)
                        == ERR_OK);
                CUT_ASSERT(memcmp(result, modulus, sidl) == 0);
                CUT_ASSERT(cid_len == mask_len + 1);
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
    test_quic_lb_ocid();
    test_quic_lb_scid();
    test_quic_lb_bcid();
}
#else
CUT_SUITE(quic_lb);
CUT_SUITE_TEST(quic_lb, test_quic_lb_ocid);
CUT_SUITE_TEST(quic_lb, test_quic_lb_scid);
CUT_SUITE_TEST(quic_lb, test_quic_lb_bcid);
#endif
