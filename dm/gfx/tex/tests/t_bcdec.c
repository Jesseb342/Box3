#include "../nvn_bcdec.h"
#include "../bc_soft.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
enum { BC6H_S=150, BC6H_U=151, BC7=152, BC7_S=153, RG11B10F=92, RGBA16F=115, RGBA8=70, RGBA8_S=71, ASTC4_S=186, ASTC4=204 };
static int failures;
#define CHECK(c,m) do { if(!(c)){fprintf(stderr,"FAIL: %s\n",m);failures++;} } while(0)
int main(void) {
    uint32_t pf=0; int bpp=0; uint8_t block[16]={0x40}, out[128]={0}, ref[16]={0}, zero[16]={0};
    nvn_bc_soft=1; nvn_bc_astc=1;
    CHECK(nvn_bc_mtl_pf(0x4d)==BC7&&nvn_bc_mtl_pf(0x4e)==BC7_S&&nvn_bc_mtl_pf(0x4f)==BC6H_S&&nvn_bc_mtl_pf(0x50)==BC6H_U,"NVN→Metal BC source mapping");
    CHECK(nvn_bc_soft_unpacked(0x4d,&pf,&bpp)&&pf==RGBA8&&bpp==4,"BC7 RGBA8 upload target");
    CHECK(nvn_bc_soft_unpacked(0x4e,&pf,&bpp)&&pf==RGBA8_S&&bpp==4,"sRGB BC7 RGBA8 target");
    CHECK(nvn_bc_soft_unpacked(0x50,&pf,&bpp)&&pf==RG11B10F&&bpp==4,"unsigned BC6H packed target");
    CHECK(nvn_bc_soft_unpacked(0x4f,&pf,&bpp)&&pf==RGBA16F&&bpp==8,"signed BC6H target");
    CHECK(nvn_bc_unpacked(0x4d,&pf,&bpp)&&pf==RGBA8&&bpp==4,"legacy BC7 RGBA path remains for 3D");
    CHECK(nvn_bc_unpacked(0x50,&pf,&bpp)&&pf==RGBA16F&&bpp==8,"legacy BC6H RGBA path remains for 3D");
    CHECK(bc_soft_block(BC7,block,ref,16)==0,"reference BC7 RGBA block");
    CHECK(nvn_bc_soft_decode(0x4d,block,16,4,4,out,16)==0&&!memcmp(out,ref,64),"NVN BC7 decoder produces RGBA block");
    memset(out,0xa5,sizeof out);
    CHECK(nvn_bc_soft_decode(0x50,zero,16,4,4,out,16)==0,"NVN BC6H unsigned decode");
    int black=1;for(int i=0;i<64;i++)black &= out[i]==0;CHECK(black,"NVN BC6H unsigned output is packed black");
    nvn_bc_astc=0;
    CHECK(nvn_bc_soft_unpacked(0x4d,&pf,&bpp)&&pf==RGBA8&&bpp==4,"BC7 RGBA8 override");
    CHECK(nvn_bc_soft_unpacked(0x50,&pf,&bpp)&&pf==RGBA16F&&bpp==8,"BC6H RGBA16F override");
    nvn_bc_soft=0;
    CHECK(!nvn_bc_soft_unpacked(0x4d,&pf,&bpp),"compact decoder disabled when nvn_bc_soft is zero");
    if(failures){fprintf(stderr,"%d NVN BC integration tests failed\n",failures);return 1;}
    puts("NVN BC integration tests passed");return 0;
}
