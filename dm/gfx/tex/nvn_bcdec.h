// GPUs without BC compressed format support (A15 / A16 etc., Apple GPU family Apple8 and below): BC textures are decompressed on the CPU into uncompressed formats.
// BC1–5 retain the existing upload paths. Non-3D BC6H/BC7 use bc_soft's compact ASTC/R11G11B10F targets when the device has no native BC support; 3D remains on the legacy RGBA decode.
#pragma once
#include <stddef.h>
#include <stdint.h>

// NVN format is BC → returns 1, *mtl_pf = Metal pixel format after decompression, *bpp = bytes per pixel after decompression; returns 0 if not BC
int nvn_bc_unpacked(uint32_t nvn_fmt, uint32_t *mtl_pf, int *bpp);
// Original BC Metal pixel format for BC6H/BC7 NVN formats, or 0 for other formats.
uint32_t nvn_bc_mtl_pf(uint32_t nvn_fmt);
// Compact BC6H/BC7 target format and decoder, only when nvn_bc_soft is enabled (non-3D uploads).
int nvn_bc_soft_unpacked(uint32_t nvn_fmt, uint32_t *mtl_pf, int *bpp);
int nvn_bc_soft_decode(uint32_t nvn_fmt, const uint8_t *src, size_t pitch, uint32_t w, uint32_t h, uint8_t *dst, size_t dpitch);
// Decode a w×h pixel region through the legacy RGBA path: src is laid out by block rows; dst has dpitch bytes per pixel row. Returns 0 on success
int nvn_bc_decode(uint32_t nvn_fmt, const uint8_t *src, size_t pitch, uint32_t w, uint32_t h, uint8_t *dst, size_t dpitch);
