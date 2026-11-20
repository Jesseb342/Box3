// CPU BC decode regression tests: compact unsigned BC6H output and the existing signed/BC7 paths.
#include "../nvn_bcdec.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static int checks, fails;
#define CHECK(c, msg) do { checks++; if (!(c)) { fails++; printf("FAIL: %s\n", msg); } } while (0)
int main(void) {
    uint32_t pf = 0; int bpp = 0;
    CHECK(nvn_bc_unpacked(0x50, &pf, &bpp) && pf == 92 && bpp == 4, "unsigned BC6H must map to R11G11B10F");
    CHECK(nvn_bc_unpacked(0x4f, &pf, &bpp) && pf == 115 && bpp == 8, "signed BC6H must remain RGBA16F");
    CHECK(nvn_bc_unpacked(0x4d, &pf, &bpp) && pf == 70 && bpp == 4, "BC7 fallback must remain RGBA8 when ASTC is disabled");
    uint8_t zero[16] = {0}, out[64]; memset(out, 0xa5, sizeof out);
    CHECK(nvn_bc_decode(0x50, zero, 16, 4, 4, out, 16) == 0, "unsigned BC6H zero block decode failed");
    int all_zero = 1; for (size_t i = 0; i < sizeof out; i++) all_zero &= out[i] == 0;
    CHECK(all_zero, "unsigned BC6H zero block did not produce packed black");
    uint8_t edge[36]; memset(edge, 0xa5, sizeof edge);
    CHECK(nvn_bc_decode(0x50, zero, 16, 3, 3, edge, 12) == 0, "unsigned BC6H partial-edge decode failed");
    int edge_zero = 1; for (size_t i = 0; i < sizeof edge; i++) edge_zero &= edge[i] == 0;
    CHECK(edge_zero, "unsigned BC6H partial-edge decode wrote unexpected data");
    memset(out, 0, sizeof out);
    CHECK(nvn_bc_decode(0x4f, zero, 16, 4, 4, out, 32) == 0, "signed BC6H zero block decode failed");
    int signed_ok = 1;
    for (int i = 0; i < 16; i++) {
        const uint16_t *p = (const uint16_t *)(out + i * 8);
        signed_ok &= p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 0x3c00;
    }
    CHECK(signed_ok, "signed BC6H RGBA16F compatibility changed");
    uint8_t bc7[16] = {0x40}, rgba[64];
    CHECK(nvn_bc_decode(0x4d, bc7, 16, 4, 4, rgba, 16) == 0, "BC7 RGBA8 fallback decode failed");
    printf("%d checks, %d failed\n", checks, fails);
    return fails != 0;
}
