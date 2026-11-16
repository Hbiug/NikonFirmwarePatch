/* Host check: decode a real Z 8 NEF with nef.c, re-encode every row with lexp_enc.c, compare with the file's strip. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../z8longexp/src/nef.h"
#include "../../z8longexp/src/lexp_enc.h"
static FILE *f;
static int rd(void *c, uint32_t off, void *out, uint32_t n){(void)c;return fseek(f,off,SEEK_SET)||fread(out,1,n,f)!=n;}
static uint8_t *orig; static uint64_t pos, mismatch_at = ~0ull; static uint32_t stripb;
static int sink(void *c, const uint8_t *d, uint32_t n){(void)c;for(uint32_t i=0;i<n;i++){if(pos+i<stripb&&orig[pos+i]!=d[i]&&mismatch_at==~0ull)mismatch_at=pos+i;}pos+=n;return 0;}
int main(int argc,char**argv){
  f=fopen(argv[1],"rb");fseek(f,0,SEEK_END);uint32_t size=ftell(f);
  static int32_t fast[1u<<PSM_FAST_BITS];psm_nef_fast_table(fast);
  psm_nef n;memset(&n,0,sizeof n);n.cache=aligned_alloc(64,1<<18);n.cache_size=1<<18;n.fast=fast;
  psm_file file={rd,0,size};int st=psm_nef_open(&n,&file);if(st){printf("open %d\n",st);return 1;}
  printf("w %u h %u strip %#x bytes %#x seeds %u %u %u %u cfa %u%u%u%u\n",n.width,n.height,n.strip_offset,n.strip_bytes,n.seeds[0],n.seeds[1],n.seeds[2],n.seeds[3],n.cfa[0],n.cfa[1],n.cfa[2],n.cfa[3]);
  stripb=n.strip_bytes;orig=malloc(stripb);fseek(f,n.strip_offset,SEEK_SET);fread(orig,1,stripb,f);
  uint16_t *row=malloc(2*n.width);static uint8_t stage[65536];lexp_encoder e;lexp_enc_init(&e,n.width,n.seeds,stage,sizeof stage,sink,0);
  uint64_t sum=0;
  for(uint32_t r=0;r<n.height;r++){if(psm_nef_row(&n,r,row,n.width)){printf("decode row %u\n",r);return 1;}for(uint32_t x=0;x<n.width;x++)sum+=row[x];if(lexp_enc_row(&e,row)){printf("enc row %u\n",r);return 1;}}
  lexp_enc_finish(&e,1);
  printf("mean %.2f encoded %llu strip %u mismatch %lld\n",(double)sum/n.width/n.height,(unsigned long long)pos,stripb,(long long)mismatch_at);
  if(pos<=stripb){int tailz=1;for(uint64_t i=pos;i<stripb;i++)if(orig[i])tailz=0;printf("tail after encoded bytes is zero: %d (%llu bytes)\n",tailz,(unsigned long long)(stripb-pos));}
  return mismatch_at!=~0ull;
}
