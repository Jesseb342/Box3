#ifndef BOX3_REWRITE_BRIDGE_H
#define BOX3_REWRITE_BRIDGE_H
#include <stddef.h>
#include <stdint.h>
typedef struct Box3RewriteResult Box3RewriteResult;
int32_t box3_rewrite_nso(const uint8_t *, size_t, const char *, const char *, const char *, Box3RewriteResult **, char *, size_t);
const uint8_t *box3_rewrite_image(const Box3RewriteResult *, size_t *);
const uint8_t *box3_rewrite_patch(const Box3RewriteResult *, size_t *);
const uint8_t *box3_rewrite_fixups(const Box3RewriteResult *, size_t *);
const uint8_t *box3_rewrite_gates(const Box3RewriteResult *, size_t *);
const uint8_t *box3_rewrite_sites(const Box3RewriteResult *, size_t *);
const uint8_t *box3_rewrite_cuts(const Box3RewriteResult *, size_t *);
const uint8_t *box3_rewrite_changed(const Box3RewriteResult *, size_t *);
const uint8_t *box3_rewrite_obs(const Box3RewriteResult *, size_t *);
size_t box3_rewrite_pad_to(const Box3RewriteResult *);
void box3_rewrite_free(Box3RewriteResult *);
#endif
