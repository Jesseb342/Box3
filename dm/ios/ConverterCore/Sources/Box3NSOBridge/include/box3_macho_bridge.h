#ifndef BOX3_MACHO_BRIDGE_H
#define BOX3_MACHO_BRIDGE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
int32_t box3_macho_assemble(const char *host_path, const char *output_path,
    const char *game_dir, const char *modules_csv, const char *tag,
    uint64_t *out_size, char *error, size_t error_capacity);
#ifdef __cplusplus
}
#endif
#endif
