#include "../bc_soft.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
enum { BC6H_S=150, BC6H_U=151, BC7=152, BC7_S=153, RG11B10F=92, RGBA16F=115, RGBA8=70, ASTC4_S=186, ASTC4=204 };
static int failures;
#define CHECK(c,m) do { if(!(c)){fprintf(stderr,"FAIL: %s\n",m);failures++;} } while(0)
int main(void) {
    uint8_t zero[16]={0}, out[128], block[16]={0}, astc[16], whole[16];
    int bpp=0; nvn_bc_astc=1;
    CHECK(bc_soft_target(BC6H_U,&bpp)==RG11B10F&&bpp==4,"unsigned BC6H compact target");
    CHECK(bc_soft_target(BC6H_S,&bpp)==RGBA16F&&bpp==8,"signed BC6H target");
    CHECK(bc_soft_target(BC7,&bpp)==ASTC4&&bpp==4,"BC7 ASTC target");
    CHECK(bc_soft_target(BC7_S,&bpp)==ASTC4_S&&bpp==4,"sRGB BC7 ASTC target");
    CHECK(bc_soft_rows(BC7,5)==2,"ASTC block-row count");
    CHECK(bc_soft_rows(BC6H_U,5)==8,"packed BC6H padded pixel rows");
    CHECK(bc_soft_decode(BC6H_U,zero,16,4,4,out,16)==0,"unsigned BC6H zero decode");
    int black=1;for(int i=0;i<64;i++)black &= out[i]==0;CHECK(black,"unsigned BC6H zero block is black");
    CHECK(bc_soft_decode(BC6H_S,zero,16,4,4,out,32)==0,"signed BC6H zero decode");
    int alpha=1;for(int i=0;i<16;i++){uint16_t a;memcpy(&a,out+i*8+6,2);alpha &= a==0x3c00;}CHECK(alpha,"signed BC6H alpha is one");
    block[0]=0x40;CHECK(bc_soft_out_block(BC7,block,astc,16)==0,"BC7 ASTC block encode");
    CHECK(bc_soft_decode(BC7,block,16,4,4,whole,16)==0&&!memcmp(astc,whole,16),"BC7 block and texture output match");
    nvn_bc_astc=0;
    CHECK(bc_soft_target(BC7,&bpp)==RGBA8&&bpp==4,"BC7 RGBA8 override");
    CHECK(bc_soft_target(BC6H_U,&bpp)==RGBA16F&&bpp==8,"BC6H RGBA16F override");
    if(failures){fprintf(stderr,"%d BC software tests failed\n",failures);return 1;}
    puts("BC software decoder tests passed");return 0;
}
