/* Adapted from zenvyzenshiro/NXNativeWindows (MIT License; Copyright 2026 ZenvyZenshiro). See repository LICENSE for terms. */
// Software decoding of BC1–BC7 textures, for GPUs that cannot sample them (MTLDevice.supportsBCTextureCompression is NO: Apple A16 and older iPhone / iPad GPUs).
// nvn_fmt_to_mtl maps BC6H/BC7 to the target formats below while nvn_bc_soft is set; BC1–5 retain their existing fallback paths.
// Pure C, no dependency on Metal headers; values are MTLPixelFormat numbers.
#pragma once
#include <stddef.h>
#include <stdint.h>

// Public, prefixed MTLPixelFormat numeric values for the format mapper and tests.
// Prefixing avoids collisions with the private format enums in nvn_fmt_mtl.c and bc_soft.c.
enum {
    BC_SOFT_BC1 = 130, BC_SOFT_BC1_S = 131, BC_SOFT_BC2 = 132, BC_SOFT_BC2_S = 133,
    BC_SOFT_BC3 = 134, BC_SOFT_BC3_S = 135, BC_SOFT_BC4_U = 140, BC_SOFT_BC4_S = 141,
    BC_SOFT_BC5_U = 142, BC_SOFT_BC5_S = 143, BC_SOFT_BC6H_S = 150, BC_SOFT_BC6H_U = 151,
    BC_SOFT_BC7 = 152, BC_SOFT_BC7_S = 153,
    BC_SOFT_R8U = 10, BC_SOFT_R8S = 12, BC_SOFT_RG8U = 30, BC_SOFT_RG8S = 32,
    BC_SOFT_RGBA8 = 70, BC_SOFT_RGBA8_S = 71, BC_SOFT_RG11B10F = 92, BC_SOFT_RGBA16F = 115,
    BC_SOFT_ASTC4_S = 186, BC_SOFT_ASTC4 = 204
};

extern int nvn_bc_soft;   // 1 = BC textures are decoded on the CPU (set once the Metal device is known; DM_BC_SOFT=1 forces it, =0 turns it off)

// The uncompressed Metal format a BC Metal format decodes to and its bytes per pixel; 0 when mtl_pf is no BC format
//   BC1 / BC2 / BC3 / BC7 (and sRGB) → ASTC 4x4 LDR (sRGB), or RGBA8Unorm (_sRGB) with nvn_bc_astc 0; BC4 → R8Unorm / R8Snorm, BC5 → RG8Unorm / RG8Snorm,
//   BC6H → RG11B10Float (unsigned, nvn_bc_astc) / RGBA16Float
uint32_t bc_soft_target(uint32_t mtl_pf, int *bytes_per_pixel);
// Rows of the decoded level in the staging layout: ceil(h / 4) * 4 pixel rows, or ceil(h / 4) block rows for ASTC 4x4 (nvn_bc_astc)
size_t bc_soft_rows(uint32_t mtl_pf, uint32_t h);
extern int nvn_bc_astc;   // 1 (the default) = BC1 / 2 / 3 / 7 become ASTC 4x4 and BC6H unsigned RG11B10F; 0 = RGBA8 / RGBA16F

// Decode a w × h region of BC blocks (src: rows of 4 × 4 blocks, src_pitch bytes from one block row to the next) into dst (dst_pitch bytes per pixel row).
// dst must hold whole blocks: ceil(w / 4) * 4 pixels per row and ceil(h / 4) * 4 rows. Returns 0, or -1 when mtl_pf is no BC format
int bc_soft_decode(uint32_t mtl_pf, const uint8_t *src, size_t src_pitch, uint32_t w, uint32_t h, uint8_t *dst, size_t dst_pitch);

// One 4 × 4 block into 16 pixels (row-major, bytes_per_pixel each), for tests
int bc_soft_block(uint32_t mtl_pf, const uint8_t *block, uint8_t *out, size_t out_pitch);
// One 4 × 4 block as the upload writes it (an ASTC 4x4 block, RG11B10F pixels, or bc_soft_block's pixels), for tests
int bc_soft_out_block(uint32_t mtl_pf, const uint8_t *block, uint8_t *out, size_t out_pitch);
