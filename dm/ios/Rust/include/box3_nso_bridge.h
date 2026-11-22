#ifndef BOX3_NSO_BRIDGE_H
#define BOX3_NSO_BRIDGE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct Box3NsoModule Box3NsoModule;
int32_t box3_nso_load(const uint8_t *data, size_t data_len, Box3NsoModule **out_module, char *error, size_t error_capacity);
const uint8_t *box3_nso_image(const Box3NsoModule *module, size_t *out_len);
int32_t box3_nso_metadata(const Box3NsoModule *module, uint32_t *segments, uint32_t *bss, uint8_t *build_id);
void box3_nso_free(Box3NsoModule *module);
#ifdef __cplusplus
}
#endif
#endif
