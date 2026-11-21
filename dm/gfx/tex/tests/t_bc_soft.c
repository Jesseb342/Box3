#include "../bc_soft.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
enum { BC6H_S=150, BC6H_U=151, BC7=152, BC7_S=153, RG11B10F=92, RGBA16F=115, RGBA8=70, RGBA8_S=71 };
static int failures;
#define CHECK(c,m) do { if(!(c)){fprintf(stderr,"FAIL: %s\n",m);failures++;} } while(0)
int main(void) {
    uint8_t zero[16]={0}, out[128], block[16]={0}, whole[64], pixels[64];
    int bpp=0; nvn_bc_astc=1;
    CHECK(bc_soft_target(BC6H_U,&bpp)==RG11B10F&&bpp==4,"unsigned BC6H compact target");
    CHECK(bc_soft_target(BC6H_S,&bpp)==RGBA16F&&bpp==8,"signed BC6H target");
    CHECK(bc_soft_target(BC7,&bpp)==RGBA8&&bpp==4,"BC7 RGBA8 target");
    CHECK(bc_soft_target(BC7_S,&bpp)==RGBA8_S&&bpp==4,"sRGB BC7 RGBA8 target");
    CHECK(bc_soft_rows(BC7,5)==8,"BC7 RGBA pixel-row count");
    CHECK(bc_soft_rows(BC6H_U,5)==8,"packed BC6H padded pixel rows");
    CHECK(bc_soft_decode(BC6H_U,zero,16,4,4,out,16)==0,"unsigned BC6H zero decode");
    int black=1;for(int i=0;i<64;i++)black &= out[i]==0;CHECK(black,"unsigned BC6H zero block is black");
    CHECK(bc_soft_decode(BC6H_S,zero,16,4,4,out,32)==0,"signed BC6H zero decode");
    int alpha=1;for(int i=0;i<16;i++){uint16_t a;memcpy(&a,out+i*8+6,2);alpha &= a==0x3c00;}CHECK(alpha,"signed BC6H alpha is one");
    block[0]=0x40;CHECK(bc_soft_block(BC7,block,pixels,16)==0,"BC7 RGBA block decode");
    CHECK(bc_soft_out_block(BC7,block,whole,16)==0&&!memcmp(pixels,whole,64),"BC7 upload block matches RGBA decoder");
    nvn_bc_astc=0;
    CHECK(bc_soft_target(BC7,&bpp)==RGBA8&&bpp==4,"BC7 RGBA8 override");
    CHECK(bc_soft_target(BC6H_U,&bpp)==RGBA16F&&bpp==8,"BC6H RGBA16F override");
    if(failures){fprintf(stderr,"%d BC software tests failed\n",failures);return 1;}
    puts("BC software decoder tests passed");return 0;
}
