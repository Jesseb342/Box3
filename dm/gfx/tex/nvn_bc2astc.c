// See nvn_bc2astc.h. The transcoder itself is bc2astc_core.h.
#include "nvn_bc2astc.h"
#include "bc2astc_core.h"
#include <string.h>
#include "../../third_party/bcdec/bcdec.h"

/*
 * BC7-to-ASTC endpoint-fit encoder adapted from NXNativeWindows:
 * https://github.com/zenvyzenshiro/NXNativeWindows
 * Copyright (c) 2026 seedds
 * Copyright (c) 2026 ZenvyZenshiro
 *
 * MIT License
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
static const uint8_t BC_ASTC_W2[4] = {0, 21, 43, 64};
static const uint8_t BC_ASTC_W3[8] = {0, 9, 18, 27, 37, 46, 55, 64};
static const uint8_t *bc_astc_weights(int bits) { return bits == 2 ? BC_ASTC_W2 : BC_ASTC_W3; }
static void put_bits(uint8_t *o, int pos, uint32_t v, int n) { for (int i = 0; i < n; i++) if (v >> i & 1) o[(pos + i) >> 3] |= (uint8_t)(1u << ((pos + i) & 7)); }
static void astc_write(uint8_t *o, int nc, int e[2][4], const uint8_t *wi, int wbits) {
    uint8_t m[16];
    if (e[1][0] + e[1][1] + e[1][2] < e[0][0] + e[0][1] + e[0][2]) {
        for (int c = 0; c < 4; c++) { int t = e[0][c]; e[0][c] = e[1][c]; e[1][c] = t; }
        for (int i = 0; i < 16; i++) m[i] = (uint8_t)((1 << wbits) - 1 - wi[i]);
        wi = m;
    }
    memset(o, 0, 16);
    put_bits(o, 0, wbits == 2 ? 0x42 : 0x53, 11); put_bits(o, 13, nc == 3 ? 8 : 12, 4);   // bits 12:11 = 0: one partition
    for (int c = 0; c < nc; c++) { put_bits(o, 17 + 16 * c, (uint32_t)e[0][c], 8); put_bits(o, 25 + 16 * c, (uint32_t)e[1][c], 8); }
    for (int i = 0; i < 16; i++)
        for (int k = 0; k < wbits; k++) if (wi[i] >> k & 1) { int b = 127 - (i * wbits + k); o[b >> 3] |= (uint8_t)(1u << (b & 7)); }
}
static int clamp255(float v) { int i = (int)(v + 0.5f); return i < 0 ? 0 : i > 255 ? 255 : i; }
// px: 16 texels RGBA8, row-major. Fit: the principal axis (power iteration from the bounding box diagonal), endpoints at the extreme projections, nearest weights, then one
// least-squares pass on the endpoints for those weights and the weights again
static void astc_encode(const uint8_t *px, uint8_t *o) {
    int opaque = 1; for (int i = 0; i < 16; i++) if (px[i * 4 + 3] != 255) { opaque = 0; break; }
    int nc = opaque ? 3 : 4, wbits = opaque ? 3 : 2, nl = 1 << wbits; const uint8_t *W = bc_astc_weights(wbits);
    float m[4] = {0}, lo[4] = {255, 255, 255, 255}, hi[4] = {0};
    for (int i = 0; i < 16; i++) for (int c = 0; c < nc; c++) { float v = px[i * 4 + c]; m[c] += v; if (v < lo[c]) lo[c] = v; if (v > hi[c]) hi[c] = v; }
    for (int c = 0; c < nc; c++) m[c] /= 16;
    float cv[4][4] = {{0}};
    for (int i = 0; i < 16; i++) for (int a = 0; a < nc; a++) for (int b = 0; b < nc; b++) cv[a][b] += (px[i * 4 + a] - m[a]) * (px[i * 4 + b] - m[b]);
    float ax[4] = {0}; for (int c = 0; c < nc; c++) ax[c] = hi[c] - lo[c];
    for (int it = 0; it < 4; it++) {
        float n[4] = {0}, l = 0;   // scaled by the largest component (no square root: the projections below divide by the axis's squared length)
        for (int a = 0; a < nc; a++) { for (int b = 0; b < nc; b++) n[a] += cv[a][b] * ax[b]; float q = n[a] < 0 ? -n[a] : n[a]; if (q > l) l = q; }
        if (l < 1e-12f) break;
        l = 1.0f / l; for (int a = 0; a < nc; a++) ax[a] = n[a] * l;
    }
    float al = 0; for (int c = 0; c < nc; c++) al += ax[c] * ax[c];
    int e[2][4] = {{0, 0, 0, 255}, {0, 0, 0, 255}}; uint8_t wi[16] = {0};
    if (al < 1e-12f) { for (int c = 0; c < nc; c++) e[0][c] = e[1][c] = clamp255(m[c]); astc_write(o, nc, e, wi, wbits); return; }   // one colour
    float tmin = 1e30f, tmax = -1e30f;
    for (int i = 0; i < 16; i++) { float d = 0; for (int c = 0; c < nc; c++) d += (px[i * 4 + c] - m[c]) * ax[c]; if (d < tmin) tmin = d; if (d > tmax) tmax = d; }
    for (int c = 0; c < nc; c++) { e[0][c] = clamp255(m[c] + ax[c] * tmin / al); e[1][c] = clamp255(m[c] + ax[c] * tmax / al); }
    for (int pass = 0; pass < 2; pass++) {
        float d[4], dd = 0; for (int c = 0; c < nc; c++) { d[c] = (float)(e[1][c] - e[0][c]); dd += d[c] * d[c]; }
        for (int i = 0; i < 16; i++) {
            float f = 0; if (dd > 0) { for (int c = 0; c < nc; c++) f += (px[i * 4 + c] - e[0][c]) * d[c]; f = f / dd * 64; }
            int best = 0; float bd = 1e30f; for (int k = 0; k < nl; k++) { float q = f - W[k]; q *= q; if (q < bd) { bd = q; best = k; } }
            wi[i] = (uint8_t)best;
        }
        if (pass) break;
        float aa = 0, ab = 0, bb = 0, ra[4] = {0}, rb[4] = {0};   // least squares: p ≈ (1 - w) e0 + w e1
        for (int i = 0; i < 16; i++) { float w = W[wi[i]] / 64.0f, u = 1 - w; aa += u * u; ab += u * w; bb += w * w; for (int c = 0; c < nc; c++) { ra[c] += u * px[i * 4 + c]; rb[c] += w * px[i * 4 + c]; } }
        float det = aa * bb - ab * ab;
        if (det < 1e-6f) break;
        for (int c = 0; c < nc; c++) { e[0][c] = clamp255((ra[c] * bb - rb[c] * ab) / det); e[1][c] = clamp255((rb[c] * aa - ra[c] * ab) / det); }
    }
    astc_write(o, nc, e, wi, wbits);
}
// BC1 four-colour block (c0 > c1): the same palette in ASTC, CEM 8 with 2-bit weights (indices 0 1 2 3 = weights 0 3 1 2)


int nvn_bc_astc_fmt(uint32_t f, uint32_t *pf, int *kind) {
    // NVN: 0x41 RGB_DXT1, 0x42 RGBA_DXT1, 0x43 DXT3, 0x44 DXT5, 0x45–0x48 the same in sRGB
    if (f >= 0x41 && f <= 0x48) {
        *pf = f >= 0x45 ? 186 : 204;
        *kind = (f & 3) == 1 || (f & 3) == 2 ? 1 : ((f & 3) == 3 ? 2 : 3);
        return 1;
    }
    if (f == 0x4d || f == 0x4e) { *pf = f == 0x4e ? 186 : 204; *kind = 4; return 1; }
    return 0;
}

uint32_t nvn_bc2astc_block(int kind, const uint8_t *bc, uint8_t *astc) {
    if (kind == 4) { uint8_t rgba[64]; bcdec_bc7(bc, rgba, 16); astc_encode(rgba, astc); return 0; }
    uint32_t w[4] = {0, 0, 0, 0}, o[4];
    memcpy(w, bc, kind == 1 ? 8 : 16);
    uint32_t r = bca_transcode(w, (u32)kind, o);
    memcpy(astc, o, 16);
    return r;
}

int nvn_bc2astc(uint32_t f, const uint8_t *src, size_t pitch, uint32_t w, uint32_t h, uint8_t *dst, size_t dpitch) {
    uint32_t pf; int kind; if (!nvn_bc_astc_fmt(f, &pf, &kind)) return -1;
    size_t bb = kind == 1 ? 8 : 16;
    for (uint32_t by = 0; by * 4 < h; by++) for (uint32_t bx = 0; bx * 4 < w; bx++)
        nvn_bc2astc_block(kind, src + by * pitch + bx * bb, dst + by * dpitch + (size_t)bx * 16);
    return 0;
}

void nvn_astc_zero_block(uint8_t out[16]) {
    static const uint8_t z[16] = {0xFC, 0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};   // void-extent block, colour 0
    memcpy(out, z, 16);
}
