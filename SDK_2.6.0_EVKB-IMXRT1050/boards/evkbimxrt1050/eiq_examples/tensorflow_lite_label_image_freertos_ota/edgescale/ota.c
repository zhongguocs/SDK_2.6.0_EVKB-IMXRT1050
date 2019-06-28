
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"
#include "http_parser.h"
#include "http_parser_url.h"
#include "hyperflash_flexspi.h"
#include "http_client.h"
#include "image.h"
#include "mbedtls/sha256.h"
#include "eds_credential.h"
#include "eds_config.h"
#include "agent.h"

#include "board.h"
#include "mbedtls/debug.h"

/* flash partitions: ... */
/* for patition 2 */
#define FLASH_SLOT1_OFFSET       (7 * 1024 * 1024ul)
#define FLASH_SLOT1_SIZE         (1024 * 1024ul)
/* for the ota log partition */
#define FLASH_SLOT2_OFFSET       (16 * 1024 * 1024ul)
#define FLASH_SLOT2_SIZE         (256 * 1024ul)
#define FLASH_WRITE_BLOCK_SIZE          2ul
#define FLASH_WRITE_BLOCK_MASK          (FLASH_WRITE_BLOCK_SIZE - 1) 

#define OTA_LOG_BASE             (FlexSPI_AMBA_BASE + FLASH_SLOT2_OFFSET)
#define FLASH_ADDR_TO_OFFSET(x)    ((void *)(x) - (FlexSPI_AMBA_BASE))
#define min(a,b)                 ((a) < (b) ? a : b)

#define OTA_FLAG_ON      0
#define OTA_FLAG_OFF     0x0fffful

#define MAX_FLASH_ALIGN         8
#define BOOT_FLAG_SET           1

#define OTA_BUFFER_SIZE     4096

#define EDS_FILE_SERVER    "storage.edgescale.org"

struct ota_log {
    uint16_t update_flag;
    uint16_t write_flag;
    uint16_t _reserve[6];
    char mid[64];
    char imageurl[512];
    char token[TOKEN_SIZE];
};

struct image_trailer {
    uint8_t copy_done;
    uint8_t pad1[MAX_FLASH_ALIGN - 1];
    uint8_t image_ok;
    uint8_t pad2[MAX_FLASH_ALIGN - 1];
    uint8_t magic[16];
} image_trailer;

#define IMAGE_TRAILER_SIZE     sizeof(struct image_trailer)

const uint32_t boot_img_magic[] = {
    0xf395c277,
    0x7fefd260,
    0x0f505235,
    0x8079b62c,
};

extern void BOARD_reset(void);
void ota_save_status(char *url, char *mid);

static uint32_t get_image1_base(void)
{
    return (FlexSPI_AMBA_BASE + FLASH_SLOT1_OFFSET);
}

int ota_status_report(char *status, char *mid, char *token)
{
    const char url[128];
    const char  header[512];
    uint8_t body[256];
    uint8_t *buf;
    int ret;
    char *version = "1903";

    buf = pvPortMalloc(1024);

    snprintf((char *)url, sizeof(url), "https://%s/v1/devices/tasks/status",
            ES_API_HOST);
    snprintf((char *)header, sizeof(header),
             "Content-Type: application/json; version=%s\r\naccess-token: %s\r\nAccept: */*\r\n", version, token);

    snprintf((char *)body, sizeof(body),
             "{\"device\":\"%s\",\"mid\":\"%s\",\"status\":\"%s\"}",
             CLIENT_ID, mid, status);

    ret = https_post(url, header, buf, 1024,
                     tlsAWS_SERVER_CA_1B, (const char *)body);
    if (ret < 0) {
        configPRINTF(("http post error"));
        return -1;
    }

    vPortFree(buf);
    return 0;
}

/* write the image trailer at the end of the flash partition */
static void enable_image1(void)
{
    uint32_t off;

    memset((void *)&image_trailer, 0xff, IMAGE_TRAILER_SIZE);
    memcpy((void *)image_trailer.magic, boot_img_magic, sizeof(boot_img_magic));

    image_trailer.image_ok= BOOT_FLAG_SET;

    off = FLASH_SLOT1_OFFSET + FLASH_SLOT1_SIZE - IMAGE_TRAILER_SIZE;

    configPRINTF(("write OK flag: off = 0x%x\r\n", off));

    flash_flexspi_write(off, (void *)&image_trailer, IMAGE_TRAILER_SIZE);
}

/* validate the image, use sha256 */
static int image_validate(void)
{
    mbedtls_sha256_context sha256_ctx;
    struct image_header ihead;
    struct image_tlv_info info;
    struct image_tlv tlv;
    uint8_t hash_result[32];
    uint8_t image_hash[32];
    uint32_t data_len;
    uint32_t start, end;
    uint32_t off;
    uint16_t has_sha256;

    /* get image1 header */
    off = get_image1_base();
    start = off;
    memcpy((void *)&ihead, (void *)off, sizeof(ihead));
    data_len = ihead.ih_hdr_size + ihead.ih_img_size;

    off += data_len;
    memcpy((void *)&info, (void *)off, sizeof(info));
    
    if (info.it_magic != IMAGE_TLV_INFO_MAGIC) {
        configPRINTF(("has no image validation data"));
        return -1;
    }

    end = off + info.it_tlv_tot;

    off += sizeof(info);
    has_sha256 = 0;
    while (off < end) {
        memcpy((void *)&tlv, (void *)off, sizeof(tlv));
        if (tlv.it_type == IMAGE_TLV_SHA256) {
            memcpy((void *)image_hash, (void *)(off + sizeof(tlv)),
                   sizeof(image_hash));
            has_sha256 = 1;
            break;
        }
        off += tlv.it_len + sizeof(tlv);
    }

    if (!has_sha256) {
        configPRINTF(("did not find SHA256 hash"));
        return -1;
    }

    mbedtls_sha256_init(&sha256_ctx);

    mbedtls_sha256_starts(&sha256_ctx, 0);

    mbedtls_sha256_update(&sha256_ctx, (void *)start, data_len);

    mbedtls_sha256_finish(&sha256_ctx, hash_result);

    if (memcmp((void *)image_hash, (void *)hash_result,
               sizeof(image_hash))) {
        configPRINTF(("the sha256 hash of the OTA image is not valid"));
        return -1;
    }

    configPRINTF(("image verified!\r\n"));

    return 0;
}

/* every flag uses 2 bytes */
static void ota_set_flag_on(void *addr)
{
    uint16_t flag_on = OTA_FLAG_ON;
    uint16_t *flag = (uint16_t *)addr;
   
    if (*flag == 0x0ffff)
        flash_flexspi_write((off_t)FLASH_ADDR_TO_OFFSET(addr),
                            (void *)&flag_on, sizeof(uint16_t));
}

int do_ota(char *image_url, char *mid)
{
    struct http_ctx *ctx;
    const unsigned char *ca;
    int ret = -1;
    uint32_t image1_offset = FLASH_SLOT1_OFFSET;
    struct url_part *url;
    uint32_t byte_count;
    uint32_t flash_offset;
    uint16_t remain;
    int retry_count = 3;
    uint8_t *ota_buf = NULL;
    struct ota_log *log;

    configPRINTF(("start OTA\r\n"));

    agent_access_token();
    PRINTF("token: %c%c%c%c...\r\n",
            api_token[0], api_token[1], api_token[2], api_token[3]);

    ota_save_status(image_url, mid);

    ota_status_report(AGENT_OTA_START, mid, api_token);

    url = pvPortMalloc(sizeof(struct url_part));
    ota_buf = pvPortMalloc(OTA_BUFFER_SIZE);

    ret = parse_http_url(image_url, url);
    if (ret) {
        goto err;
    }

    vTaskDelay(pdMS_TO_TICKS(1000));

retry:
    /* erase flash image 1 */
    ret = flash_flexspi_erase(image1_offset, FLASH_SLOT1_SIZE);
    if (ret) {
        configPRINTF(("fail to erase flash"));
        goto err1;
    }

    if (strstr(url->server, EDS_FILE_SERVER) != NULL) {
        ca = tlsAWS_SERVER_CA_1B;
    } else {
        ca = NULL;
    }

    ota_status_report(AGENT_OTA_FETCH, mid, api_token);

    /* create a http ctx */
    ctx = http_open(url->server, url->port, ca);
    if (ctx == NULL) {
        configPRINTF(("error to connect server"));
        goto err1;
    }

    /* send http request */
    ret = http_send(ctx, url->path, HTTP_GET, NULL, NULL);
    if (!ret) {
        configPRINTF(("error to send HTTP request"));
        goto err2;
    }

    /* download OTA image */
    byte_count = 0;
    flash_offset = 0;
    remain = 0;
    while(1) {
        ret = http_recv(ctx, ota_buf + remain,
                        OTA_BUFFER_SIZE - remain, 3000 /* ms */);
        if (ret <= 0) {
            configPRINTF(("error to receive HTTP packet"));
            goto err2;
        }

        PRINTF(".");

        byte_count += ret;
        remain = byte_count % OTA_BUFFER_SIZE;

        if ((remain == 0) && (byte_count != 0)) {
            flash_flexspi_write(image1_offset + flash_offset,
                                (void *)ota_buf,
                                OTA_BUFFER_SIZE);
            flash_offset += OTA_BUFFER_SIZE;
        }

        /* check if get the whole image */
        if (byte_count == ctx->http.rsp.content_length) {
            if (remain != 0) {
                /* align */
                remain = remain & FLASH_WRITE_BLOCK_MASK ?
                        (remain + FLASH_WRITE_BLOCK_SIZE) & ~FLASH_WRITE_BLOCK_MASK
                        : remain;
                flash_flexspi_write(image1_offset + flash_offset,
                                    (void *)ota_buf,
                                    remain);
            }
            //DISPLAY_MEM_USAGE
            break;
        }
    }

    PRINTF("\r\n");
    http_close(ctx);
    configPRINTF(("OTA: received %d bytes\r\n", byte_count));

    /* validate the image */
    if (image_validate())
        goto err1;

    ota_status_report(AGENT_OTA_VERIFY, mid, api_token);

    vPortFree(url);
    vPortFree(ota_buf);

    enable_image1();

    log = (struct ota_log *)OTA_LOG_BASE;
    ota_set_flag_on((void *)&log->write_flag);

    return 0;

err2:
    http_close(ctx);
err1:
    if (retry_count > 1) {
        retry_count--;
        goto retry;
    }
err:
    vPortFree(url);
    vPortFree(ota_buf);
    return -1;
}

void check_ota_status(void)
{
    struct ota_log *log;
    int ret;

    log = (struct ota_log *)OTA_LOG_BASE;

    if (log->update_flag == OTA_FLAG_ON &&
        log->write_flag == OTA_FLAG_ON) {
        /* OTA completes successfully */
        PRINTF("token: %c%c%c%c...\r\n",
               log->token[0], log->token[1], log->token[2], log->token[3]);
        ota_status_report(AGENT_OTA_COMPLETE, log->mid, log->token);
        ret = flash_flexspi_erase(FLASH_SLOT2_OFFSET, FLASH_SLOT2_SIZE);
        if (ret) {
            configPRINTF(("fail to erase flash"));
            goto err;
        }
    } else if (log->update_flag == OTA_FLAG_ON &&
               log->write_flag == OTA_FLAG_OFF) {
        /* received an OTA message, but not complete */
        ret = do_ota(log->imageurl, log->mid);
        if (ret) {
            configPRINTF(("OTA failed"));
            goto err;
        }
        ota_status_report(AGENT_OTA_REBOOT, log->mid, log->token);
        vTaskDelay(pdMS_TO_TICKS(500));
        BOARD_reset();
        /* never return */
    }
err:
    return;
}

static int empty_flash_slot2(void)
{
    uint16_t count = 0;
    uint32_t *p;

retry:
    p = (uint32_t *)OTA_LOG_BASE;
    for ( ; p < (uint32_t *)(OTA_LOG_BASE + FLASH_SLOT2_SIZE); p++) {
        if (*p != 0x0ffffffff) {
            flash_flexspi_erase(FLASH_SLOT2_OFFSET, FLASH_SLOT2_SIZE);
            count++;
            if (count <= 1)
                goto retry;
            else
                goto err;
        }
    }
    return 0;
err:
    return -1;
}

void ota_save_status(char *url, char *mid)
{
    struct ota_log *log;
    struct ota_log *dst = (struct ota_log *)OTA_LOG_BASE;
    int ret;

    log = pvPortMalloc(sizeof(struct ota_log));
    if (log == NULL)
        goto err;

    memset((void *)log, 0x0ff, sizeof(struct ota_log));

    strncpy(log->imageurl, url, min(sizeof(log->imageurl), strlen(url) + 1));
    strncpy(log->mid, mid, min(sizeof(log->mid), strlen(mid) + 1));
    strncpy(log->token, (const char *)api_token, min(sizeof(log->token),
            strlen(api_token) + 1));
    log->update_flag = OTA_FLAG_ON;

    /* make sure the flash area, SLOT2, is empty */
    ret = empty_flash_slot2();
    if (ret) {
        configPRINTF(("the flash area, SLOT2, can not be erased"));
        goto err;
    }

    ret = flash_flexspi_write((off_t)FLASH_ADDR_TO_OFFSET(dst), (void *)log,
                              sizeof(struct ota_log));
    if (ret) {
        configPRINTF(("flash write error"));
        goto err;
    }

    return;
err:
    return;
}
