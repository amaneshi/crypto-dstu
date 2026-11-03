/* Test-only Cryptonite reference adapter; deliberately public scalars d=2, peer=7. */
#include <stdio.h>
#include <stdlib.h>
#include "dstu4145.h"
#include "byte_array.h"

static void check(int code) {
    if (code) { fprintf(stderr,"Cryptonite error %d\n",code); exit(1); }
}
static void field(const char *name,const ByteArray *value) {
    size_t n=ba_get_len(value); const unsigned char *p=ba_get_buf(value);
    printf("\"%s\":\"",name);
    while(n) printf("%02x",p[--n]);
    printf("\"");
}
int main(void) {
    const int degrees[]={163,167,173,179,191,233,257,307,367,431,173,179,191,233,431};
    printf("{\"sourceCommit\":\"3618d340d22e27a6becf97d89c453f8e64068a39\","
           "\"producer\":\"Cryptonite dstu4145_dh with_cofactor=false; public d=2, peer d=7\",\"vectors\":[");
    for(int i=0;i<15;i++) {
        Dstu4145Ctx *ctx=dstu4145_alloc((Dstu4145ParamsId)(i+1));
        ByteArray *d=ba_alloc_from_le_hex_string("02"),*peer=ba_alloc_from_le_hex_string("07");
        ByteArray *qx=NULL,*qy=NULL,*zx=NULL,*zy=NULL;
        if(!ctx||!d||!peer) return 1;
        check(dstu4145_get_pubkey(ctx,peer,&qx,&qy));
        check(dstu4145_dh(ctx,false,d,qx,qy,&zx,&zy));
        printf("%s{\"curve\":\"DSTU_%s_%d\",",i?",":"",i<10?"PB":"ONB",degrees[i]);
        field("peerX",qx);printf(",");field("peerY",qy);printf(",");field("sharedX",zx);printf("}");
        dstu4145_free(ctx);ba_free(d);ba_free(peer);ba_free(qx);ba_free(qy);ba_free(zx);ba_free(zy);
    }
    puts("]}");return 0;
}
