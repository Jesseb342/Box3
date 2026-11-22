#include "box3_nso_bridge.h"

// Keeps the public C module visible to SwiftPM; implementation lives in the Rust static library.
int box3_nso_bridge_module_anchor(void) { return 0; }
