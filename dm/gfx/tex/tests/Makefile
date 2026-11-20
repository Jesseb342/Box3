# Texture sub-module unit tests (seconds): make run
CFLAGS = -O2 -g -Wall -Wextra -fblocks
t_tex: t_tex.c ../nvn_deswizzle.c ../nvn_deswizzle.h ../../nvn/nvn_tex.c ../../nvn/nvn_tex.h
	clang $(CFLAGS) -o $@ t_tex.c ../nvn_deswizzle.c ../../nvn/nvn_tex.c -lm
t_fmt_mtl: t_fmt_mtl.m ../nvn_fmt_mtl.c ../nvn_fmt_mtl.h
	clang $(CFLAGS) -fobjc-arc -o $@ t_fmt_mtl.m ../nvn_fmt_mtl.c -framework Metal -framework Foundation
t_bc2astc: t_bc2astc.c ../nvn_bc2astc.c ../nvn_bc2astc.h ../bc2astc_core.h ../bc_soft.c ../bc_soft.h ../../../third_party/bcdec/bcdec.h
	clang $(CFLAGS) -fblocks -o $@ t_bc2astc.c ../nvn_bc2astc.c ../bc_soft.c -lm
bench_bc2astc_dread: bench_bc2astc_dread.c ../nvn_texkey.h ../nvn_bc2astc.c ../nvn_bc2astc.h ../bc2astc_core.h ../bc2astc_body.inc ../nvn_deswizzle.c ../../nvn/nvn_tex.c
	clang $(CFLAGS) -Wno-unused -o $@ bench_bc2astc_dread.c ../nvn_bc2astc.c ../nvn_deswizzle.c ../../nvn/nvn_tex.c -lz -lm
# Real-data benchmark (Dread-specific, game data stays outside the repository): make bench ROMFS=<extracted RomFS> ASTCENC=<astcenc> OUT=<report folder> [KEEP='<keep table.tsv> 27']
bench: bench_bc2astc_dread
	mkdir -p $(OUT) && ./bench_bc2astc_dread $(ROMFS) $(ASTCENC) $(OUT) $(KEEP)
t_bc_soft: t_bc_soft.c ../bc_soft.c ../bc_soft.h
	clang $(CFLAGS) -fblocks -o $@ t_bc_soft.c ../bc_soft.c

t_bcdec: t_bcdec.c ../nvn_bcdec.c ../nvn_bcdec.h ../bc_soft.c ../bc_soft.h ../../../third_party/bcdec/bcdec.h
	clang $(CFLAGS) -fblocks -o $@ t_bcdec.c ../nvn_bcdec.c ../bc_soft.c

run: t_tex t_fmt_mtl t_bc_soft t_bcdec
	./t_fmt_mtl && ./t_tex && ./t_bc_soft && ./t_bcdec
# Needs the astcenc binary (ARM-software/astc-encoder): make ASTCENC=/path/to/astcenc astc
astc: t_bc2astc
	ASTCENC=$(ASTCENC) ./t_bc2astc
.PHONY: run astc bench
