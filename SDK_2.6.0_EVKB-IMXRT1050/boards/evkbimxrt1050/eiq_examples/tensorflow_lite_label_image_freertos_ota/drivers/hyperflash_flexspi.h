
#ifndef _SOURCE_HYPERFLASH_FLEXSPI_H
#define _SOURCE_HYPERFLASH_FLEXSPI_H

#include <string.h>

#define off_t _off_t

int flash_flexspi_init(void);

int flash_flexspi_erase(off_t offset, size_t len);
int flash_flexspi_read(off_t offset, void *data, size_t len);
int flash_flexspi_write(off_t offset, const void *data, size_t len);


#endif
