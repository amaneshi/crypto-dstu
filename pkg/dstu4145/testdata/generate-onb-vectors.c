/* Test-only Cryptonite adapter. All scalars and PRNG seeds are intentionally
 * public. Never use these keys or deterministic seeds outside fixtures. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dstu4145.h"
#include "byte_array_internal.h"

static void check(int code) {
    if (code != 0) { fprintf(stderr, "Cryptonite error %d\n", code); exit(1); }
}
static void field(const char *name, const ByteArray *value) {
    const uint8_t *bytes = ba_get_buf(value);
    size_t length = ba_get_len(value);
    printf("\"%s\":\"", name);
    while (length != 0) printf("%02x", bytes[--length]);
    printf("\"");
}
int main(int argc, char **argv) {
    const int degrees[] = {173, 179, 191, 233, 431};
    unsigned char seed_bytes[40], hash_bytes[32];
    int i, j;
    for (i = 0; i < 40; i++) seed_bytes[i] = (unsigned char)i;
    for (i = 0; i < 32; i++) hash_bytes[i] = (unsigned char)i;
    if (argc==2 && !strcmp(argv[1],"zero")) memset(hash_bytes,0,sizeof(hash_bytes));
    printf("{\"sourceCommit\":\"3618d340d22e27a6becf97d89c453f8e64068a39\",\"producer\":\"Cryptonite dstu4145 public API; public d=2, peer d=7; seed bytes 00..27\",\"vectors\":[");
    for (j = 0; j < 5; j++) {
        Dstu4145Ctx *ctx = dstu4145_alloc((Dstu4145ParamsId)(11+j));
        ByteArray *d = ba_alloc_from_le_hex_string("02");
        ByteArray *peer = ba_alloc_from_le_hex_string("07");
        ByteArray *seed = ba_alloc_from_uint8(seed_bytes, sizeof(seed_bytes));
        ByteArray *hash = ba_alloc_from_uint8(hash_bytes, sizeof(hash_bytes));
        ByteArray *qx = NULL, *qy = NULL, *compressed = NULL;
        ByteArray *px = NULL, *py = NULL, *peer_compressed = NULL;
        ByteArray *zx = NULL, *zy = NULL, *r = NULL, *s = NULL;
        PrngCtx *prng = prng_alloc(PRNG_MODE_DSTU, seed);
        if (!ctx || !prng || !d || !peer || !hash) return 1;
        check(dstu4145_get_pubkey(ctx, d, &qx, &qy));
        check(dstu4145_compress_pubkey(ctx, qx, qy, &compressed));
        check(dstu4145_get_pubkey(ctx, peer, &px, &py));
        check(dstu4145_compress_pubkey(ctx, px, py, &peer_compressed));
        check(dstu4145_dh(ctx, true, d, px, py, &zx, &zy));
        check(dstu4145_init_sign(ctx, d, prng));
        check(dstu4145_sign(ctx, hash, &r, &s));
        check(dstu4145_init_verify(ctx, qx, qy));
        check(dstu4145_verify(ctx, hash, r, s));
        printf("%s{\"degree\":%d,", j ? "," : "", degrees[j]);
        field("digest", hash); printf(",");
        field("qx", qx); printf(","); field("qy", qy); printf(",");
        field("compressed", compressed); printf(",");
        field("peerCompressed", peer_compressed); printf(",");
        field("sharedX", zx); printf(",");
        field("r", r); printf(","); field("s", s); printf("}");
        dstu4145_free(ctx); prng_free(prng);
        ba_free(d); ba_free(peer); ba_free(seed); ba_free(hash);
        ba_free(qx); ba_free(qy); ba_free(compressed);
        ba_free(px); ba_free(py); ba_free(peer_compressed);
        ba_free(zx); ba_free(zy); ba_free(r); ba_free(s);
    }
    printf("]}\n");
    return 0;
}
