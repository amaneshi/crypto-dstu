/* Bounded test-only DER reader plus unmodified UAPKIC hashing/signature APIs.
 * Public disposable self-signed certificates/CSRs only; no trust/issuance claim.
 * Reference: specinfo-ua/UAPKI 1996c0fe56dbbc69f5b00d67784a5bc3033b57fe. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dstu4145.h"
#include "dstu7564.h"

typedef struct { const unsigned char *p; size_t n; } span;
static void require_at(int ok,int line) { if(!ok){fprintf(stderr,"invalid modern ONB fixture or reference failure at %d\n",line);exit(1);} }
#define need(ok) require_at((ok),__LINE__)
static span take(span *in,int tag) {
    size_t n=0,count,i;span out;need(in->n>=2&&in->p[0]==tag);
    count=in->p[1];in->p+=2;in->n-=2;
    if(!(count&128))n=count;
    else {count&=127;need(count>0&&count<=4&&in->n>=count&&in->p[0]);for(i=0;i<count;i++)n=(n<<8)|in->p[i];in->p+=count;in->n-=count;need(n>=128);}
    need(n<=in->n);out=(span){in->p,n};in->p+=n;in->n-=n;return out;
}
static span algorithm(span value) {
    span result=take(&value,6);
    if(value.n){span null=take(&value,5);need(!null.n&&!value.n);}
    return result;
}
static ByteArray *ba(span value){return ba_alloc_from_uint8(value.p,value.n);}
int main(int argc,char **argv) {
    unsigned char bytes[1<<20],point[64];size_t size,i;FILE *file;int is_csr,mode,index,m,selector,trace,nonzero;
    const int degrees[]={173,179,191,233,431};
    const unsigned char gost_onb[]={0x2a,0x86,0x24,2,1,1,1,1,3,1,2};
    const unsigned char kupyna[]={0x2a,0x86,0x24,2,1,1,1,1,3,6};
    span all,outer,body,aid,sigalg,tbs_alg={NULL,0},spki,parameters,curve,key,raw,signature;
    ByteArray *message,*hash=NULL,*compressed,*qx=NULL,*qy=NULL,*r,*s;EcCtx *ctx;Dstu7564Ctx *h;
    need(argc==3&&(!strcmp(argv[1],"csr")||!strcmp(argv[1],"cert")));is_csr=!strcmp(argv[1],"csr");
    file=fopen(argv[2],"rb");need(file!=NULL);size=fread(bytes,1,sizeof(bytes),file);need(!ferror(file)&&feof(file));fclose(file);
    all=(span){bytes,size};outer=take(&all,0x30);need(!all.n);
    const unsigned char *signed_start=outer.p;body=take(&outer,0x30);message=ba((span){signed_start,(size_t)(outer.p-signed_start)});
    aid=take(&outer,0x30);sigalg=algorithm(aid);
    need(sigalg.n==12&&!memcmp(sigalg.p,kupyna,10)&&sigalg.p[11]==2&&(sigalg.p[10]==1||sigalg.p[10]==3));
    mode=sigalg.p[10]==1?32:64;
    signature=take(&outer,3);need(!outer.n&&signature.n&&!signature.p[0]);signature.p++;signature.n--;
    raw=take(&signature,4);need(!signature.n&&raw.n&&!(raw.n&1));r=ba((span){raw.p,raw.n/2});s=ba((span){raw.p+raw.n/2,raw.n/2});
    if(is_csr){span version=take(&body,2);need(version.n==1&&!version.p[0]);}
    else {
        span version=take(&body,0xa0),v=take(&version,2);need(!version.n&&v.n==1&&v.p[0]==2);
        take(&body,2);tbs_alg=algorithm(take(&body,0x30));need(tbs_alg.n==sigalg.n&&!memcmp(tbs_alg.p,sigalg.p,sigalg.n));
        take(&body,0x30);take(&body,0x30);
    }
    take(&body,0x30);spki=take(&body,0x30);
    if(is_csr){span attributes=take(&body,0xa0);need(!attributes.n&&!body.n);}
    else {if(body.n)take(&body,0xa3);need(!body.n);}
    aid=take(&spki,0x30);raw=take(&aid,6);need(raw.n==sizeof(gost_onb)&&!memcmp(raw.p,gost_onb,sizeof(gost_onb)));
    parameters=take(&aid,0x30);need(!aid.n);curve=take(&parameters,6);
    need(curve.n==13&&!memcmp(curve.p,gost_onb,sizeof(gost_onb))&&curve.p[11]==2&&curve.p[12]<5);
    index=curve.p[12];m=degrees[index];
    span dke=take(&parameters,4);need(dke.n==64&&!parameters.n);
    key=take(&spki,3);need(!spki.n&&key.n&&!key.p[0]);key.p++;key.n--;raw=take(&key,4);need(!key.n&&raw.n==(size_t)(m+7)/8&&raw.n<=sizeof(point));
    memcpy(point,raw.p,raw.n);need(!(point[raw.n-1]>>(m%8)));
    nonzero=0;for(i=0;i<raw.n;i++)nonzero|=point[i];
    if(nonzero){
        unsigned char mask=(unsigned char)(1u<<((m-1)%8));selector=(point[(m-1)/8]&mask)!=0;trace=0;
        for(i=0;i<raw.n;i++){unsigned char v=point[i];while(v){trace^=v&1;v>>=1;}}
        if(trace!=(index==0?0:1))point[(m-1)/8]^=mask;
        nonzero=0;for(i=0;i<raw.n;i++)nonzero|=point[i];need(nonzero);
        /* The pinned reference uses the legacy bit-0 compressor. Only this
         * adapter transcodes the wire selector; crypto source is unmodified. */
        point[0]=(unsigned char)((point[0]&0xfe)|selector);
    }
    ctx=ec_alloc_default((EcParamsId)(11+index));need(ctx!=NULL);compressed=ba((span){point,raw.n});
    need(!dstu4145_decompress_pubkey(ctx,compressed,&qx,&qy));
    /* The DSTU decoder returns LE fields; the generic EC verifier takes BE. */
    need(!ba_swap(qx)&&!ba_swap(qy));need(!ec_init_verify(ctx,qx,qy));
    h=dstu7564_alloc();need(h!=NULL);need(!dstu7564_init(h,(size_t)mode));need(!dstu7564_update(h,message));need(!dstu7564_final(h,&hash));
    need(!dstu4145_verify(ctx,hash,r,s));
    ec_free(ctx);dstu7564_free(h);ba_free(message);ba_free(hash);ba_free(compressed);ba_free(qx);ba_free(qy);ba_free(r);ba_free(s);
    puts("UAPKIC modern ONB signature verified");return 0;
}
