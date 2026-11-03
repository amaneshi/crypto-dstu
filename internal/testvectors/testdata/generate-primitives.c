/* Test-only adapter to the pinned, unmodified Cryptonite library. Public bytes only. */
#include <stdio.h>
#include <stdlib.h>
#include "byte_array_internal.h"
#include "dstu7564.h"
#include "dstu7624.h"
#include "gost28147.h"
#include "gost34_311.h"
#include "hmac.h"

static int first = 1;
static void check(int rc) { if (rc) { fprintf(stderr, "Cryptonite error %d\n", rc); exit(1); } }
static void hex(const ByteArray *value) {
    size_t i;
    if (value) for (i = 0; i < ba_get_len(value); i++) printf("%02x", ba_get_buf(value)[i]);
}
static void emit(const char *algorithm, int block_size, const ByteArray *key,
                 const ByteArray *message, ByteArray *output) {
    printf("%s{\"algorithm\":\"%s\",\"blockSize\":%d,\"key\":\"", first ? "" : ",\n", algorithm, block_size);
    first = 0; hex(key); printf("\",\"message\":\""); hex(message);
    printf("\",\"output\":\""); hex(output); printf("\"}"); ba_free(output);
}
int main(void) {
    const size_t sizes[] = {0,1,7,8,9,31,32,33,51,52,63,64,65,111,112,127,128,129,255,256,257,1024};
    unsigned char data[1024], keys[129], zero[32] = {0};
    ByteArray *sync = ba_alloc_from_uint8(zero, sizeof(zero));
    size_t i, j, n;
    for (i = 0; i < sizeof(data); i++) data[i] = (unsigned char)(29*i+7);
    for (i = 0; i < sizeof(keys); i++) keys[i] = (unsigned char)i;
    printf("{\"sourceCommit\":\"3618d340d22e27a6becf97d89c453f8e64068a39\",\"vectors\":[\n");
    for (i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
        ByteArray *msg = ba_alloc_from_uint8(data, sizes[i]), *output = NULL;
        Gost34311Ctx *g = gost34_311_alloc(GOST28147_SBOX_ID_1, sync);
        check(gost34_311_update(g, msg)); check(gost34_311_final(g, &output));
        emit("gost34311", 0, NULL, msg, output); gost34_311_free(g);
        for (j = 0; j < 3; j++) {
            const size_t lengths[] = {32,48,64};
            const char *hashes[] = {"kupyna256","kupyna384","kupyna512"};
            const char *macs[] = {"kmac256","kmac384","kmac512"};
            Dstu7564Ctx *ctx = dstu7564_alloc(DSTU7564_SBOX_1);
            ByteArray *key = ba_alloc_from_uint8(keys, lengths[j]);
            check(dstu7564_init(ctx, lengths[j])); check(dstu7564_update(ctx, msg));
            check(dstu7564_final(ctx, &output)); emit(hashes[j], 0, NULL, msg, output);
            check(dstu7564_init_kmac(ctx, key, lengths[j])); check(dstu7564_update_kmac(ctx, msg));
            check(dstu7564_final_kmac(ctx, &output)); emit(macs[j], 0, key, msg, output);
            dstu7564_free(ctx); ba_free(key);
        }
        for (n = 1; n <= 129; n = n == 1 ? 32 : n == 32 ? 65 : n == 65 ? 129 : 130) {
            ByteArray *key = ba_alloc_from_uint8(keys, n);
            HmacCtx *ctx = hmac_alloc_gost34_311(GOST28147_SBOX_ID_1, sync);
            check(hmac_init(ctx, key)); check(hmac_update(ctx, msg)); check(hmac_final(ctx, &output));
            emit("hmac-gost34311", 0, key, msg, output); hmac_free(ctx); ba_free(key);
        }
        if (sizes[i] > 0) {
            ByteArray *key = ba_alloc_from_uint8(keys, 32);
            Gost28147Ctx *ctx = gost28147_alloc(GOST28147_SBOX_ID_1);
            check(gost28147_init_mac(ctx, key)); check(gost28147_update_mac(ctx, msg));
            check(gost28147_final_mac8(ctx, &output)); emit("gost28147-mac", 8, key, msg, output);
            gost28147_free(ctx); ba_free(key);
        }
        ba_free(msg);
    }
    for (i = 1; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
        ByteArray *key = ba_alloc_from_uint8(keys,32), *iv = ba_alloc_from_uint8(keys,8);
        ByteArray *msg = ba_alloc_from_uint8(data,sizes[i]), *output = NULL;
        Gost28147Ctx *ctx = gost28147_alloc(GOST28147_SBOX_ID_1);
        check(gost28147_init_cfb(ctx,key,iv)); check(gost28147_encrypt(ctx,msg,&output));
        emit("gost28147-cfb",8,key,msg,output);
        gost28147_free(ctx);ba_free(key);ba_free(iv);ba_free(msg);
    }
    for (j = 0; j < 5; j++) {
        const size_t blocks[] = {16,16,32,32,64}, lengths[] = {16,32,32,64,64};
        const char *modes[] = {"kalyna-ecb","kalyna-cbc","kalyna-ctr","kalyna-cfb","kalyna-ofb"};
        ByteArray *key = ba_alloc_from_uint8(keys, lengths[j]);
        ByteArray *msg = ba_alloc_from_uint8(data, 3*blocks[j]), *output = NULL;
        ByteArray *iv = ba_alloc_from_uint8(keys, blocks[j]);
        for (n = 0; n < 5; n++) {
            Dstu7624Ctx *ctx = dstu7624_alloc(DSTU7624_SBOX_1);
            switch (n) {
                case 0: check(dstu7624_init_ecb(ctx, key, blocks[j])); break;
                case 1: check(dstu7624_init_cbc(ctx, key, iv)); break;
                case 2: check(dstu7624_init_ctr(ctx, key, iv)); break;
                case 3: check(dstu7624_init_cfb(ctx, key, iv, blocks[j])); break;
                case 4: check(dstu7624_init_ofb(ctx, key, iv)); break;
            }
            check(dstu7624_encrypt(ctx, msg, &output));
            emit(modes[n], (int)blocks[j], key, msg, output); dstu7624_free(ctx);
        }
        ba_free(iv); ba_free(key); ba_free(msg);
    }
    ba_free(sync); printf("\n]}\n"); return 0;
}
