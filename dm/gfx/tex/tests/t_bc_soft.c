#include "../bc_soft.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static int failures;
#define CHECK(c, m) do { if (!(c)) { fprintf(stderr, "FAIL: %s\n", (m)); failures++; } } while (0)
int main(void) {
    uint8_t zero[16] = {0}, out[128], block[16], astc[16];
    int bpp = 0; nvn_bc_soft = 1; nvn_bc_astc = 1;
    CHECK(bc_soft_target(BC_SOFT_BC6H_U, &bpp) == BC_SOFT_RG11B10F && bpp == 4, "unsigned BC6H target");
    CHECK(bc_soft_target(BC_SOFT_BC6H_S, &bpp) == BC_SOFT_RGBA16F && bpp == 8, "signed BC6H target");
    CHECK(bc_soft_target(BC_SOFT_BC7, &bpp) == BC_SOFT_ASTC4 && bpp == 4, "BC7 ASTC target");
    CHECK(bc_soft_target(BC_SOFT_BC7_S, &bpp) == BC_SOFT_ASTC4_S && bpp == 4, "sRGB BC7 ASTC target");
    CHECK(bc_soft_rows(BC_SOFT_BC7, 5) == 2, "ASTC block-row count");
    CHECK(bc_soft_rows(BC_SOFT_BC6H_U, 5) == 8, "R11G11B10F padded row count");
    memset(out, 0xa5, sizeof out);
    CHECK(bc_soft_decode(BC_SOFT_BC6H_U, zero, 16, 4, 4, out, 16) == 0, "unsigned BC6H zero block decode");
    int black = 1; for (int i = 0; i < 64; i++) black &= out[i] == 0;
    CHECK(black, "unsigned BC6H zero block packs to black");
    memset(out, 0, sizeof out);
    CHECK(bc_soft_decode(BC_SOFT_BC6H_S, zero, 16, 4, 4, out, 32) == 0, "signed BC6H zero block decode");
    int alpha_one = 1;
    for (int i = 0; i < 16; i++) { uint16_t a; memcpy(&a, out + i * 8 + 6, 2); alpha_one &= a == 0x3c00; }
    CHECK(alpha_one, "signed BC6H output alpha is 1.0");
    memset(block, 0, sizeof block); block[0] = 0x40;
    CHECK(bc_soft_out_block(BC_SOFT_BC7, block, astc, 16) == 0, "BC7 ASTC block encode");
    uint8_t whole[16];
    CHECK(bc_soft_decode(BC_SOFT_BC7, block, 16, 4, 4, whole, 16) == 0, "BC7 ASTC decode");
    CHECK(!memcmp(astc, whole, 16), "BC7 block and texture decode match");
    nvn_bc_astc = 0;
    CHECK(bc_soft_target(BC_SOFT_BC7, &bpp) == BC_SOFT_RGBA8 && bpp == 4, "BC7 RGBA8 fallback");
    CHECK(bc_soft_target(BC_SOFT_BC6H_U, &bpp) == BC_SOFT_RGBA16F && bpp == 8, "unsigned BC6H RGBA16F fallback");
    memset(out, 0, sizeof out);
    CHECK(bc_soft_decode(BC_SOFT_BC7, block, 16, 4, 4, out, 16) == 0, "BC7 RGBA8 decode");
    if (failures) { fprintf(stderr, "%d BC soft tests failed\n", failures); return 1; }
    puts("BC soft decoder tests passed"); return 0;
}
