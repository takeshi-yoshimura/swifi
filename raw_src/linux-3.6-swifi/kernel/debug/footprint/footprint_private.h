#ifndef _FOOTPRINT_PRIVATE_H
#define _FOOTPRINT_PRIVATE_H

#include <linux/kgdb.h>
#include "../debug_core.h"

void footprint_initbptab(void);
int footprint_stub(struct kgdb_state * ks);

#endif /*_FOOTPRINT_PRIVATE_H*/
