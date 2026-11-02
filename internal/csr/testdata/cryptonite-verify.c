/* Test-only DER reader plus independent Cryptonite hashing and verification.
 * Inputs are synthetic public CSRs. This is not a production ASN.1 parser. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dstu4145.h"
#include "gost34_311.h"
#include "dstu7564.h"

typedef struct { const unsigned char *p; size_t n; } span;
static void require_at(int ok,int line) { if (!ok) { fprintf(stderr,"invalid CSR or failed reference verification at line %d\n",line); exit(1); } }
#define need(ok) require_at((ok),__LINE__)
static span take(span *in, int tag) {
    size_t n=0, count, i; span out;
    need(in->n>=2 && in->p[0]==tag);
    count=in->p[1]; in->p+=2; in->n-=2;
    if (!(count&128)) n=count;
    else { count&=127; need(count>0 && count<=4 && in->n>=count && in->p[0]);
        for(i=0;i<count;i++) n=(n<<8)|in->p[i];
        in->p+=count; in->n-=count; need(n>=128); }
    need(n<=in->n); out.p=in->p; out.n=n; in->p+=n; in->n-=n; return out;
}
static ByteArray *ba(span s) { return ba_alloc_from_uint8(s.p,s.n); }
int main(int argc,char **argv) {
    unsigned char bytes[1<<20], unpacked[128]; size_t size,i; FILE *file;
    span all,outer,info,version,subject,spki,aid,algorithm,parameters,curve,key,signature,attributes,raw;
    const unsigned char prefix[]={0x2a,0x86,0x24,2,1,1,1,1,3,1};
    ByteArray *message,*hash=NULL,*qx=NULL,*qy=NULL,*r,*s,*compressed;
    Dstu4145Ctx *ctx; int curve_id,mode=0;
    need(argc==2); file=fopen(argv[1],"rb"); need(file!=NULL);
    size=fread(bytes,1,sizeof(bytes),file); need(!ferror(file) && feof(file)); fclose(file);
    all=(span){bytes,size}; outer=take(&all,0x30); need(!all.n);
    const unsigned char *info_start=outer.p;
    info=take(&outer,0x30); message=ba((span){info_start,(size_t)(outer.p-info_start)});
    version=take(&info,2); need(version.n==1 && version.p[0]==0);
    subject=take(&info,0x30); (void)subject;
    spki=take(&info,0x30); attributes=take(&info,0xa0); need(!info.n && !attributes.n);
    aid=take(&spki,0x30); algorithm=take(&aid,6); parameters=take(&aid,0x30); need(!aid.n);
    curve=take(&parameters,6); need(curve.n==13 && !memcmp(curve.p,prefix,10) && curve.p[11]==2);
    need((curve.p[10]==1 && curve.p[12]<10)||(curve.p[10]==2 && curve.p[12]<5));
    curve_id=(curve.p[10]==1 ? 1 : 11)+curve.p[12];
    ctx=dstu4145_alloc((Dstu4145ParamsId)curve_id); need(ctx!=NULL);
    if(algorithm.n==11 && !memcmp(algorithm.p,prefix,10) && algorithm.p[10]==curve.p[10]) mode=0;
    else { const unsigned char kupyna[]={0x2a,0x86,0x24,2,1,1,1,1,3,6};
        need(curve.p[10]==1 && algorithm.n==12 && !memcmp(algorithm.p,kupyna,10) && algorithm.p[11]==1);
        need(algorithm.p[10]==1 || algorithm.p[10]==3); mode=algorithm.p[10]==1 ? 32:64; }
    if(!mode) {
        span dke=take(&parameters,4); need(dke.n==64 && !parameters.n);
        for(i=0;i<64;i++) { unpacked[2*i]=dke.p[i]>>4; unpacked[2*i+1]=dke.p[i]&15; }
        ByteArray *box=ba_alloc_from_uint8(unpacked,128),*sync=ba_alloc_by_len(32);
        ba_set(sync,0); Gost34311Ctx *h=gost34_311_alloc_user_sbox(box,sync); need(h!=NULL);
        need(!gost34_311_update(h,message)); need(!gost34_311_final(h,&hash));
        gost34_311_free(h); ba_free(box); ba_free(sync);
    } else {
        need(!parameters.n); Dstu7564Ctx *h=dstu7564_alloc(DSTU7564_SBOX_1); need(h!=NULL);
        need(!dstu7564_init(h,(size_t)mode)); need(!dstu7564_update(h,message)); need(!dstu7564_final(h,&hash)); dstu7564_free(h);
    }
    key=take(&spki,3); need(!spki.n && key.n && !key.p[0]); key.p++;key.n--; raw=take(&key,4);need(!key.n);
    compressed=ba(raw); need(!dstu4145_decompress_pubkey(ctx,compressed,&qx,&qy));
    aid=take(&outer,0x30); span sigalg=take(&aid,6); need(!aid.n && sigalg.n==algorithm.n && !memcmp(sigalg.p,algorithm.p,algorithm.n));
    signature=take(&outer,3);need(!outer.n && signature.n && !signature.p[0]);signature.p++;signature.n--;
    raw=take(&signature,4);need(!signature.n && raw.n && !(raw.n&1));
    r=ba((span){raw.p,raw.n/2});s=ba((span){raw.p+raw.n/2,raw.n/2});
    /* This pinned Cryptonite API requires exactly 32 digest bytes. */
    need(ba_get_len(hash)==32);
    need(!dstu4145_init_verify(ctx,qx,qy));
    int verified=dstu4145_verify(ctx,hash,r,s);
    if (verified) {
        fprintf(stderr,"reference digest (%d): ",mode);
        for(i=ba_get_len(hash);i>0;i--) fprintf(stderr,"%02x",ba_get_buf(hash)[i-1]);
        fputc('\n',stderr);
    }
    need(!verified);
    dstu4145_free(ctx);ba_free(message);ba_free(hash);ba_free(qx);ba_free(qy);ba_free(r);ba_free(s);ba_free(compressed);
    puts("Cryptonite CSR signature verified");return 0;
}
