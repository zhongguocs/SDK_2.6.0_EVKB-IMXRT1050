/*
 * Copyright (c) 2016 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>

#include "FreeRTOS.h"
#include "hyperflash_flexspi.h"
#include "fsl_clock.h"
#include "fsl_common.h"
#include "fsl_flexspi.h"

/* In the XIP mode, the code must be put in RAM to execute. */

#define FLASH_STATUS_READY          0x80
#define FLASH_STATUS_ERASE          0x20
#define FLASH_STATUS_PROGRAM        0x10
#define FLASH_STATUS_SECTOR_LOCK    0x02

#define HYPERFLASH_CMD_LUT_SEQ_IDX_READDATA     0    /* seq_num = 1 */
#define HYPERFLASH_CMD_LUT_SEQ_IDX_WRITEDATA    1    /* seq_num = 1 */
#define HYPERFLASH_CMD_LUT_SEQ_IDX_READSTATUS   2    /* seq_num = 2 */
#define HYPERFLASH_CMD_LUT_SEQ_IDX_RESET        4    /* seq_num = 1 */
#define HYPERFLASH_CMD_LUT_SEQ_IDX_UNLOCK       5    /* seq_num = 2 */
#define HYPERFLASH_CMD_LUT_SEQ_IDX_8            8

#define HYPERFLASH_LUT_ITEM_SIZE        16u  /* byte */
#define SEQ_NUMBER(x)       (sizeof(x) / HYPERFLASH_LUT_ITEM_SIZE)

#define FLASH_LINE_SIZE	           512u
#define FLASH_LINE_SIZE_MASK	   (FLASH_LINE_SIZE - 1)

#define FLASH_SIZE                  FLASH_SIZE_KB * 1024
#define FLASH_SIZE_KB               (64 * 1024u)
#define FLASH_WRITE_BLOCK_SIZE      2u
#define FLASH_ERASE_BLOCK_SIZE      (256 * 1024u)
#define FLASH_WRITE_BLOCK_MASK      (FLASH_WRITE_BLOCK_SIZE - 1)
#define FLASH_ERASE_BLOCK_MASK      (FLASH_ERASE_BLOCK_SIZE - 1)

#define LUT_LENGTH(x)	   (sizeof(x) / sizeof(uint32_t))

#define min(a, b) ((a) < (b) ? (a) : (b))

static FLEXSPI_Type *flexspi_base = (FLEXSPI_Type *) FLEXSPI_BASE;

flexspi_device_config_t deviceconfig = {
    .flexspiRootClk = 42000000ul,
    .isSck2Enabled = false,
    .flashSize = FLASH_SIZE_KB,
    .CSIntervalUnit = kFLEXSPI_CsIntervalUnit1SckCycle,
    .CSInterval = 2,
    .CSHoldTime = 0,
    .CSSetupTime = 3,
    .dataValidTime = 1,
    .columnspace = 3,
    .enableWordAddress = true,  /* 16 bit mode, word mode */
    .AWRSeqIndex = HYPERFLASH_CMD_LUT_SEQ_IDX_WRITEDATA,
    .AWRSeqNumber = 1,
    .ARDSeqIndex = HYPERFLASH_CMD_LUT_SEQ_IDX_READDATA,
    .ARDSeqNumber = 1,
    .AHBWriteWaitUnit = kFLEXSPI_AhbWriteWaitUnit2AhbCycle,
    .AHBWriteWaitInterval = 20,
};

/* the default LUT */
const uint32_t hyperflash_lut[] = {
    /* 0 Read Data */
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_READDATA] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0xA0,
            kFLEXSPI_Command_RADDR_DDR, kFLEXSPI_8PAD, 0x18),
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_READDATA + 1] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_CADDR_DDR, kFLEXSPI_8PAD, 0x10,
            kFLEXSPI_Command_READ_DDR, kFLEXSPI_8PAD, 0x04),
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_READDATA + 2] = 0,
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_READDATA + 3] = 0,

    /* 1 Write Data */
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_WRITEDATA] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x20,
            kFLEXSPI_Command_RADDR_DDR, kFLEXSPI_8PAD, 0x18),
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_WRITEDATA + 1] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_CADDR_DDR, kFLEXSPI_8PAD, 0x10,
            kFLEXSPI_Command_WRITE_DDR, kFLEXSPI_8PAD, 0x02),
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_WRITEDATA + 2] = 0,
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_WRITEDATA + 3] = 0,

    /* 2 Read Status */
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_READSTATUS] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x20,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00),
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_READSTATUS + 1] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0xAA), /* ADDR 0x555 */
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_READSTATUS + 2] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x05),
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_READSTATUS + 3] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x70), /* DATA 0x70 */
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_READSTATUS + 4] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0xA0,
            kFLEXSPI_Command_RADDR_DDR, kFLEXSPI_8PAD, 0x18),
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_READSTATUS + 5] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_CADDR_DDR, kFLEXSPI_8PAD, 0x10,
            kFLEXSPI_Command_DUMMY_RWDS_DDR, kFLEXSPI_8PAD, 0x0B),
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_READSTATUS + 6] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_READ_DDR, kFLEXSPI_8PAD, 0x04,
            kFLEXSPI_Command_STOP, kFLEXSPI_1PAD, 0x0),
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_READSTATUS + 7] = 0,

    /* 4 Reset/ASO Exit */
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_RESET] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x20,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00),
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_RESET + 1] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00),
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_RESET + 2] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00), /* ADDR xxx */
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_RESET + 3] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0xF0), /* DATA 0xF0 */

    /* 5 Unlock */
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_UNLOCK] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x20,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00),
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_UNLOCK + 1] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0xAA), /* ADDR 0x555 */
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_UNLOCK + 2] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x05),
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_UNLOCK + 3] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0xAA), /* DATA 0xAA */
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_UNLOCK + 4] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x20,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00),
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_UNLOCK + 5] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x55), /* ADDR 0x2AA */
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_UNLOCK + 6] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x02),
    [4 * HYPERFLASH_CMD_LUT_SEQ_IDX_UNLOCK + 7] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x55), /* DATA 0x55 */
};

/* Sector Erase LUT */
const uint32_t hyperflash_lut_erase[] = {
    /* 0 */
    [0] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x20,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00),
    [1] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0xAA), /* ADDR 0x555 */
    [2] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x05),
    [3] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0xAA), /* DATA 0xAA */
    /* 1 */
    [4] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x20,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00),
    [5] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x55), /* ADDR 0x2AA */
    [6] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x02),
    [7] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x55), /* DATA 0x55 */
    /* 2 */
    [8] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x20,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00),
    [9] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0xAA), /* ADDR 0x555 */
    [10] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x05),
    [11] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x80), /* DATA 0x80 */
    /* 3 */
    [12] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x20,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00),
    [13] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0xAA), /* ADDR 0x555 */
    [14] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x05),
    [15] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0xAA), /* DATA 0xAA */
    /* 4 */
    [16] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x20,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00),
    [17] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x55), /* ADDR 0x2AA */
    [18] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x02),
    [19] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x55), /* DATA 0x55 */
    /* 5 */
    [20] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x20,
            kFLEXSPI_Command_RADDR_DDR, kFLEXSPI_8PAD, 0x18),
    [21] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_CADDR_DDR, kFLEXSPI_8PAD, 0x10, /* SA */
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00),
    [22] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x30,    /* DATA 0x30 */
            kFLEXSPI_Command_STOP, kFLEXSPI_1PAD, 0x00),
    [23] = 0,
};

/* Word Program */
const uint32_t hyperflash_lut_wprog[] = {
    /* 0 */
    [0] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x20,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00),
    [1] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0xAA), /* ADDR 0x555 */
    [2] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x05),
    [3] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0xAA), /* DATA 0xAA */
    /* 1 */
    [4] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x20,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00),
    [5] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x55), /* ADDR 0x2AA */
    [6] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x02),
    [7] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x55), /* DATA 0x55 */
    /* 2 */
    [8] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x20,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00),
    [9] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0xAA),
    [10] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x05), /* ADDR 0x555 */
    [11] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x00,
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0xA0), /* DATA 0xA0 */
    /* 3 */
    [12] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_DDR, kFLEXSPI_8PAD, 0x20,
            kFLEXSPI_Command_RADDR_DDR, kFLEXSPI_8PAD, 0x18),
    [13] = FLEXSPI_LUT_SEQ(
            kFLEXSPI_Command_CADDR_DDR, kFLEXSPI_8PAD, 0x10, /* PA */
            kFLEXSPI_Command_WRITE_DDR, kFLEXSPI_8PAD, 0x80), /* PD */
    [14] = 0,
    [15] = 0,
};

static int flash_flexspi_read_status(void)
{
    flexspi_transfer_t flashXfer;
    uint32_t status_val;
    status_t status;

    FLEXSPI_memset(&flashXfer, 0, sizeof(flashXfer));
    flashXfer.deviceAddress = 0;
    flashXfer.port = kFLEXSPI_PortA1;
    flashXfer.cmdType = kFLEXSPI_Read;
    flashXfer.seqIndex = HYPERFLASH_CMD_LUT_SEQ_IDX_READSTATUS;
    flashXfer.SeqNumber = 2;
    flashXfer.data = &status_val;
    flashXfer.dataSize = 2;
    status = FLEXSPI_TransferBlocking(flexspi_base, &flashXfer);
    if (status != kStatus_Success) {
        return -EIO;
    }

    status_val = (int)__REV16(status_val);
    return status_val;
}

static int flash_flexspi_wait_bus_busy(void)
{
    int flash_status;
    int rc;

    while (1) {
        flash_status = flash_flexspi_read_status();
        if (flash_status < 0) {
            rc = flash_status;
            break;
        }

        if (flash_status & FLASH_STATUS_READY) {
            /* success */
            rc = 0;
            break;
        }

        if (flash_status & (FLASH_STATUS_ERASE |
                    FLASH_STATUS_PROGRAM | FLASH_STATUS_SECTOR_LOCK)) {
            /* fail */
            rc = -EIO;
            break;
        }
        /* TODO add delay */
    }

    return rc;
}

static int flash_flexspi_erase_sector(off_t addr)
{
    flexspi_transfer_t flashXfer;
    status_t status;
    int rc;

    /* addr must be a starting address of a sector */
    assert((addr & FLASH_ERASE_BLOCK_MASK) == 0);

    /* load the LUT for sector erase */
    FLEXSPI_UpdateLUT(flexspi_base, HYPERFLASH_CMD_LUT_SEQ_IDX_8 * 4,
            hyperflash_lut_erase, LUT_LENGTH(hyperflash_lut_erase));

    FLEXSPI_memset(&flashXfer, 0, sizeof(flashXfer));
    flashXfer.deviceAddress = addr;
    flashXfer.port = kFLEXSPI_PortA1;
    flashXfer.cmdType = kFLEXSPI_Command;
    flashXfer.seqIndex = HYPERFLASH_CMD_LUT_SEQ_IDX_8;
    flashXfer.SeqNumber = SEQ_NUMBER(hyperflash_lut_erase);
    status = FLEXSPI_TransferBlocking(flexspi_base, &flashXfer);
    if (status != kStatus_Success) {
        return -EIO;
    }

    rc = flash_flexspi_wait_bus_busy();
    if (rc) {
        return rc;
    }

    return 0;
}

int flash_flexspi_erase(off_t offset, size_t len)
{
    off_t start;
    int rc;

    assert((offset & FLASH_ERASE_BLOCK_MASK) == 0);
    assert((len & FLASH_ERASE_BLOCK_MASK) == 0);

    if (len < FLASH_ERASE_BLOCK_SIZE)
        goto err;

    portDISABLE_INTERRUPTS();

    start = offset;
    while (len > 0) {
        rc = flash_flexspi_erase_sector(start);
        if (rc) {
            goto err1;
        }
        len -= FLASH_ERASE_BLOCK_SIZE;
        start += FLASH_ERASE_BLOCK_SIZE;
    }

    /* invalidate cache */
    SCB_InvalidateDCache();
    SCB_InvalidateICache();
    portENABLE_INTERRUPTS();
    return 0;

err1:
    portENABLE_INTERRUPTS();
err:
    return -1;
}

static int flash_flexspi_block_program(off_t offset, const uint16_t *src,
        const size_t len)

{
    flexspi_transfer_t flashXfer;
    status_t status;
    int rc;

    /* check word alignment */
    assert((offset & FLASH_WRITE_BLOCK_MASK) == 0);
    assert((len <= FLASH_LINE_SIZE) && ((len & FLASH_WRITE_BLOCK_MASK) == 0));

    FLEXSPI_UpdateLUT(flexspi_base, HYPERFLASH_CMD_LUT_SEQ_IDX_8 * 4,
            hyperflash_lut_wprog, LUT_LENGTH(hyperflash_lut_wprog));

    FLEXSPI_memset(&flashXfer, 0, sizeof(flashXfer));
    flashXfer.deviceAddress = offset;
    flashXfer.port = kFLEXSPI_PortA1;
    flashXfer.cmdType = kFLEXSPI_Write;
    flashXfer.seqIndex = HYPERFLASH_CMD_LUT_SEQ_IDX_8;
    flashXfer.SeqNumber = SEQ_NUMBER(hyperflash_lut_wprog);
    flashXfer.data = (uint32_t *)src;
    flashXfer.dataSize = len;
    status = FLEXSPI_TransferBlocking(flexspi_base, &flashXfer);
    if (status != kStatus_Success) {
        return -EIO;
    }

    rc = flash_flexspi_wait_bus_busy();
    if (rc) {
        return rc;
    }

    return 0;
}

int flash_flexspi_write(off_t offset, const void *data, size_t len)
{
    off_t start;
    size_t size;
    uint8_t *src;
    int rc;

    /* word align */
    assert(((offset & 1) == 0) && (offset < FLASH_SIZE));
    assert(((uint32_t) data & 1) == 0);
    assert((len & 1) == 0);

    portDISABLE_INTERRUPTS();

    start = offset;
    src = (uint8_t *)data;
    while(len > 0) {
        if (start & FLASH_LINE_SIZE_MASK) {
            /* if not flash line alignment */
            size = ((start + FLASH_LINE_SIZE) & ~FLASH_LINE_SIZE_MASK) -
                start;
            size = min(size, len);
        } else {
            size = min(FLASH_LINE_SIZE, len);
        }

        rc = flash_flexspi_block_program(start, (uint16_t *)src, size);
        if (rc) {
            goto err;
        }
        start += size;
        src += size;
        len -= size;
    }

    /* invalidate cache */
    SCB_InvalidateDCache();
    SCB_InvalidateICache();
    portENABLE_INTERRUPTS();
    return 0;
err:
    portENABLE_INTERRUPTS();
    return -1;
}

int flash_flexspi_read(off_t offset, void *data, size_t len)
{
    uint32_t addr;

    addr = offset + FlexSPI_AMBA_BASE;
    memcpy(data, (void *) addr, len);

    return 0;
}

static void flash_flexspi_clock_init(void)
{
    CLOCK_DisableClock(kCLOCK_FlexSpi);
    CLOCK_SetMux(kCLOCK_FlexspiMux, 3);
    CLOCK_SetDiv(kCLOCK_FlexspiDiv, 3);
    CLOCK_EnableClock(kCLOCK_FlexSpi);
}


int flash_flexspi_init(void)
{
    flexspi_config_t config;

    vPortEnterCritical();

    /* disable flexspi */
    FLEXSPI_Enable(flexspi_base, false);

    flash_flexspi_clock_init();

    /* Get FLEXSPI default settings and configure the flexspi. */
    FLEXSPI_GetDefaultConfig(&config);

    /* Set AHB buffer for reading data through AHB bus. */
    config.ahbConfig.enableAHBPrefetch = true;
    config.ahbConfig.enableAHBBufferable = true;
    config.ahbConfig.enableAHBCachable = true;

    config.enableSckBDiffOpt = true;
    config.rxSampleClock = kFLEXSPI_ReadSampleClkExternalInputFromDqsPad;
    config.enableCombination = true;
    FLEXSPI_Init(flexspi_base, &config);

    /* AHB Read Address option bit. This option bit is intend to remove
     * AHB burst start address alignment limitation
     */
    FLEXSPI->AHBCR |= FLEXSPI_AHBCR_READADDROPT_MASK;

    /* Update LUT table. */
    FLEXSPI_UpdateLUT(flexspi_base, 0, hyperflash_lut,
                      LUT_LENGTH(hyperflash_lut));

    /* Configure flash settings according to serial flash feature. */
    FLEXSPI_SetFlashConfig(flexspi_base, &deviceconfig, kFLEXSPI_PortA1);

    /* enable flexspi */
    FLEXSPI_Enable(flexspi_base, true);

    /* Do software reset. */
    FLEXSPI_SoftwareReset(flexspi_base);

    vPortExitCritical();

    return 0;
}
