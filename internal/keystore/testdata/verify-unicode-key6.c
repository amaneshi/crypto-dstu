/* Test-only bounded public-fixture adapter. Include the pinned, unmodified
 * UAPKI pkcs5.c so its original password KDF is tested, not a copied loop.
 * Source revision: 1996c0fe56dbbc69f5b00d67784a5bc3033b57fe. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include UAPKI_PKCS5_SOURCE
static void need(int ok){if(!ok){fputs("Unicode privacy check failed\n",stderr);exit(1);}}
static unsigned char input[16384];static size_t used,size;
static unsigned number(void){unsigned v;need(size-used>=4);v=(unsigned)input[used]|((unsigned)input[used+1]<<8)|((unsigned)input[used+2]<<16)|((unsigned)input[used+3]<<24);used+=4;return v;}
static ByteArray *field(unsigned limit){unsigned n=number();ByteArray *b;need(n<=limit&&n<=size-used);b=ba_alloc_from_uint8(input+used,n);need(b!=NULL);used+=n;return b;}
int main(int argc,char **argv){
 FILE *f;char password[33];unsigned n,iterations;ByteArray *salt,*iv,*cipher,*expected,*key=NULL,*plain=NULL;Dstu7624Ctx *ctx;size_t len,padding,i;
 need(argc==2);f=fopen(argv[1],"rb");need(f!=NULL);size=fread(input,1,sizeof(input),f);need(!ferror(f)&&feof(f));fclose(f);
 need(size>=4&&!memcmp(input,"UKP1",4));used=4;n=number();need(n>0&&n<=32&&n<=size-used&&!memchr(input+used,0,n));memcpy(password,input+used,n);password[n]=0;used+=n;
 salt=field(1024);iterations=number();need(iterations>0&&iterations<=10000);iv=field(32);need(ba_get_len(iv)==32);cipher=field(4096);expected=field(4096);need(used==size);
 need(!pbkdf2_dstu7564kmac(password,salt,iterations,32,HASH_ALG_DSTU7564_256,&key));
 ctx=dstu7624_alloc(DSTU7624_SBOX_1);need(ctx!=NULL);need(!dstu7624_init_cbc(ctx,key,iv));need(!dstu7624_decrypt(ctx,cipher,&plain));
 len=ba_get_len(plain);need(len>0);padding=ba_get_buf_const(plain)[len-1];need(padding>0&&padding<=32&&padding<=len);
 for(i=len-padding;i<len;i++)need(ba_get_buf_const(plain)[i]==padding);
 need(len-padding==ba_get_len(expected)&&!memcmp(ba_get_buf_const(plain),ba_get_buf_const(expected),len-padding));
 ba_free_private(key);ba_free_private(plain);ba_free(salt);ba_free(iv);ba_free(cipher);ba_free(expected);dstu7624_free(ctx);memset(password,0,sizeof(password));
 puts("UAPKI Unicode privacy verified");return 0;
}
