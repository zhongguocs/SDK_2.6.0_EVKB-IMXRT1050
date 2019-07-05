
#include <stdio.h>
#include <string.h>

#include "board.h"
#include "FreeRTOS.h"
#include "task.h"
#include "timers.h"
#include "jsmn.h"
#include "lwip/netif.h"
#include "http_type.h"
#include "http_client.h"

#include "eds_config.h"
#include "eds_credential.h"
#include "aws_mqtt_agent.h"
#include "agent.h"

#define MQTT_TIMEOUT     pdMS_TO_TICKS(3000)   /* 3 second */
#define MSG_SIZE         512

#define PUSH_PERIOD      4u  /* seconds */
#define CLIENT_TOPIC   "device/" CLIENT_ID
#define STATUS_TOPIC   "edgescale/health/internal/system/status"

#define WDOG_FEED_PERIOD    5  /* seconds */

#define MAX_JSON_TOKEN      64
#define AGENT_QUEUE_SIZE    2

extern void BOARD_reset(void);

extern struct netif fsl_netif0;
static MQTTAgentHandle_t mqtt_handle;

const char mqtt_server[] = MQTT_SERVER;
const uint16_t mqtt_server_port = MQTT_PORT;
const char mqtt_status_topic[] = STATUS_TOPIC;
const char client_topic[] = CLIENT_TOPIC;
const char client_id[] = CLIENT_ID;

static TimerHandle_t report_timer;
static TimerHandle_t wdog_timer;

static char *esversion = "edgescale-1809";
static size_t cpu_usage = 1;  /* percent */
static size_t mem_usage;      /* percent */
static QueueHandle_t agent_queue = NULL;
char *api_token = NULL;

enum msg_action {
    MSG_ACT_UPDATE_FIRMWARE = 0,
    MSG_ACT_UNENROLL        = 1,
    MSG_ACT_UPLOADLOG       = 2,
    MSG_ACT_UPDATE_SOFTWARE = 3,
    MSG_ACT_RESET           = 4,
    MSG_ACT_MAX
};

char *action_value[] = {
   [MSG_ACT_UPDATE_FIRMWARE] = "update_firmware",
   [MSG_ACT_UNENROLL]        = "unenroll",
   [MSG_ACT_UPLOADLOG]       = "uploadlog",
   [MSG_ACT_UPDATE_SOFTWARE] = "update_software",
   [MSG_ACT_RESET]           = "reset"
};

/* 
message for update firmware
{
   "action" : "",
   "model_id" : "",
   "mid" : "",
   "solution" : "",
   "version" : "",
   "url" : "",
   "type" : ""
}
*/

#define KEY_ACTION     "action"
#define KEY_URL        "url"
#define KEY_MID        "mid"

struct message {
    char *action;
//    char *model_id;
    char *mid;
//    char *solution;
    char *version;
    char *url;
//    char *type;
    char _buf[MSG_SIZE];
};

struct queue_struct {
    uint32_t length;
    char buf[MSG_SIZE - 4];
};

static void system_statistic(void)
{
	size_t mem_use;

	mem_use = 0;//configTOTAL_HEAP_SIZE - xPortGetFreeHeapSize();
	mem_usage = mem_use * 100 / configTOTAL_HEAP_SIZE;
    configPRINTF(("memory usage: %d percent\r\n", mem_usage));

    //DISPLAY_MEM_USAGE
}

static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
    if (tok->type == JSMN_STRING &&
        (int) strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

static void init_msg(struct message *msg)
{
    msg->action = 0;
    msg->version = 0;
    msg->url = 0;
    memset(msg->_buf, 0, sizeof(msg->_buf));
}

static int parse_message(struct message *msg, char *jstring, size_t length)
{
    jsmn_parser parser;
    jsmntok_t jsmn_array[MAX_JSON_TOKEN];
    jsmntok_t *jsmn;
    int len;
    int count;
    int buf_index = 0;
    int i;

    configPRINTF(("Received message:\r\n"));
    configPRINTF(("%s\r\n", jstring));

    init_msg(msg);
    jsmn_init(&parser);
    count = jsmn_parse(&parser, jstring, length, jsmn_array, MAX_JSON_TOKEN);
    if (count == 0)
        goto err;

    for (i = 0; i < count; i++) {
        jsmn = &jsmn_array[i];

        if (jsmn->type == JSMN_OBJECT)
            continue;

        len = 0;
        if (jsoneq(jstring, jsmn, KEY_ACTION) == 0) {
            jsmn++;
            i++;
            len = jsmn->end - jsmn->start;
            strncpy(&msg->_buf[buf_index], jstring + jsmn->start, len);
            msg->action = &msg->_buf[buf_index];
            buf_index += len + 1;
        } else if (jsoneq(jstring, jsmn, KEY_URL) == 0) {
            jsmn++;
            i++;
            len = jsmn->end - jsmn->start;
            strncpy(&msg->_buf[buf_index], jstring + jsmn->start, len);
            msg->url = &msg->_buf[buf_index];
            buf_index += len + 1;
        } else if (jsoneq(jstring, jsmn, KEY_MID) == 0) {
            jsmn++;
            i++;
            len = jsmn->end - jsmn->start;
            strncpy(&msg->_buf[buf_index], jstring + jsmn->start, len);
            msg->mid = &msg->_buf[buf_index];
            buf_index += len + 1;
        } else {
            i++;
            continue;
        }

        if (buf_index >= MSG_SIZE)
            break;
    }

    return 0;

err:
    return -1;
}

void stop_mqtt(void)
{
	MQTTAgentSubscribeParams_t sub_param;
	MQTTAgentReturnCode_t mqtt_ret;

    /* stop timer */
    xTimerStop(report_timer, pdMS_TO_TICKS(100));

    /* unsubscribe topic */
	memset(&sub_param, 0, sizeof(sub_param));
	sub_param.pucTopic = (uint8_t *) client_topic;
	sub_param.usTopicLength = strlen(client_topic);
    mqtt_ret = MQTT_AGENT_Unsubscribe(mqtt_handle, &sub_param, MQTT_TIMEOUT);
	if (mqtt_ret != eMQTTAgentSuccess)
	{
        configPRINTF( ( "ERR: could not unsubscribe to %s\r\n", client_topic) );
	}

    vTaskDelay(pdMS_TO_TICKS(500));

    MQTT_AGENT_Disconnect(mqtt_handle, MQTT_TIMEOUT);

    /* close mqtt agent */
    MQTT_AGENT_Delete(mqtt_handle);
}

static void process_message(char *buf, uint32_t size)
{
    struct message msg;
    int index;

    if (parse_message(&msg, (char *)buf, size)) {
        configPRINTF(("Error message format!\r\n"));
        goto err;
    }

    if (msg.action == 0) {
        configPRINTF(("Error message!\r\n"));
        goto err;
    }

    for(index = 0; index < MSG_ACT_MAX; index++) {
        if (strncmp(action_value[index], msg.action,
                        strlen(action_value[index])) == 0 )
            break;
    }
   
    switch(index) {
        case MSG_ACT_UPDATE_FIRMWARE:
            /* update image */
            configPRINTF(("update_firmware\r\n"));
            if (msg.url == 0) {
                configPRINTF(("Do not know the image url!\r\n"));
                break;
            }

            /* stop mqtt to prevent multithread TLS problem */
            stop_mqtt();

            if (do_ota(msg.url, msg.mid) == 0) {
                ota_status_report(AGENT_OTA_REBOOT, msg.mid, api_token);
                vTaskDelay(pdMS_TO_TICKS(1000));
                BOARD_reset();
                /* never return */
            }
            break;
        case MSG_ACT_UNENROLL:
            break;
        case MSG_ACT_UPLOADLOG:
            break;
        case MSG_ACT_UPDATE_SOFTWARE:
            break;
        case MSG_ACT_RESET:
            BOARD_reset();
            break;
        default:
        	break;
    }

err:
    return;
}

static MQTTBool_t mqtt_callback(void *user_data,
				const MQTTPublishData_t * const data)
{
    int ret;
    struct queue_struct buf;

    configASSERT(agent_queue);

    ret = memcmp(data->pucTopic, client_topic, strlen(client_topic));
    if (ret)
        goto err;

    if (data->ulDataLength <= MSG_SIZE - 4) {
        buf.length = data->ulDataLength;
        memcpy((void *)buf.buf, data->pvData, data->ulDataLength);
        xQueueSendToBack(agent_queue, (const void *)&buf, 0);
    } else {
        configPRINTF(("Error message size!"));
    }

    /* return the buffer */
    MQTT_AGENT_ReturnBuffer(mqtt_handle, data->xBuffer);
    return eMQTTTrue;

err:
    return eMQTTFalse;
}

static int agent_sub_topic(void)
{
	MQTTAgentReturnCode_t mqtt_ret;
	MQTTAgentSubscribeParams_t sub_param;

	memset(&sub_param, 0, sizeof(sub_param));
	sub_param.pucTopic = (uint8_t *) client_topic;
	sub_param.usTopicLength = strlen(client_topic);
	sub_param.pvPublishCallbackContext = NULL;
	sub_param.pxPublishCallback = mqtt_callback;
	sub_param.xQoS = eMQTTQoS1;
	mqtt_ret = MQTT_AGENT_Subscribe(mqtt_handle, &sub_param, MQTT_TIMEOUT);
	if (mqtt_ret != eMQTTAgentSuccess)
	{
        configPRINTF( ( "ERR: could not subscribe to %s\r\n", client_topic) );
		return -1;
	}

	configPRINTF(("subscribe topic:\r\n"));
	configPRINTF(("%s\r\n", client_topic));
	return 0;
}

static int agent_init(void)
{
    MQTTAgentReturnCode_t mqtt_ret;
	MQTTAgentConnectParams_t conn_param;


	mqtt_ret = MQTT_AGENT_Create(&mqtt_handle);
	if (mqtt_ret != eMQTTAgentSuccess)
	{
		configPRINTF(( "ERR: MQTT_AGENT_Create: fail\r\n"));
        goto err;
	}

    memset(&conn_param, 0, sizeof(conn_param));
    conn_param.pcURL = mqtt_server;
    conn_param.usPort = mqtt_server_port;
    conn_param.pucClientId = (const uint8_t *)client_id;
	conn_param.usClientIdLength = (uint16_t) strlen(client_id);

    conn_param.xFlags = mqttagentREQUIRE_TLS;
    conn_param.pcCertificate = (char *)tlsEDGESCALE_ROOT_CERTIFICATE_PEM;
    conn_param.ulCertificateSize = tlsEDGESCALE_ROOT_CERTIFICATE_SIZE;

	mqtt_ret = MQTT_AGENT_Connect(mqtt_handle, &conn_param,
                                        pdMS_TO_TICKS( 12000 )); 
	if (mqtt_ret != eMQTTAgentSuccess)
	{
		configPRINTF(( "ERR: MQTT_AGENT_Connect: fail\r\n"));
		MQTT_AGENT_Delete(mqtt_handle);
        goto err;
	}

    return 0;
err:
    return -1;
}

#define STATUS_FMT      "{\"id\":\"%s\","               \
                        "\"cpuusage\":\"%d%%\","         \
                        "\"memusage\":\"%d%%\","        \
                        "\"appnumber\": \"1\","         \
                        "\"esversion\": \"%s\","    \
                        "\"ipaddress\": \"%s\" }"

static int agent_push_status(void)
{
	MQTTAgentPublishParams_t publish_param;
    MQTTAgentReturnCode_t mqtt_ret;
    char buf[MSG_SIZE];
    char ipaddr[64];

	snprintf(ipaddr, sizeof(ipaddr),"%u.%u.%u.%u",
						((u8_t *)&fsl_netif0.ip_addr.addr)[0],
						((u8_t *)&fsl_netif0.ip_addr.addr)[1],
						((u8_t *)&fsl_netif0.ip_addr.addr)[2],
						((u8_t *)&fsl_netif0.ip_addr.addr)[3]);

	snprintf(buf, sizeof(buf), STATUS_FMT,
			 client_id, cpu_usage, mem_usage, esversion, ipaddr);

    memset(&publish_param, 0, sizeof(publish_param));
    publish_param.pucTopic = (uint8_t *) mqtt_status_topic;
    publish_param.usTopicLength = strlen(mqtt_status_topic);
    publish_param.xQoS = eMQTTQoS1;
    publish_param.pvData = buf;
    publish_param.ulDataLength = strlen(buf);
    mqtt_ret = MQTT_AGENT_Publish(mqtt_handle, &publish_param, MQTT_TIMEOUT);
    if (mqtt_ret != eMQTTAgentSuccess)
    {
        configPRINTF(("Err: MQTT_AGENT_Publish: ret(%d)\r\n", mqtt_ret));
        /* TODO reconnect */
        return -1;
    }

    return 0;
}

static void agent_report(TimerHandle_t xTimer)
{
    configPRINTF(("publish report ...\r\n"));
    system_statistic();
    agent_push_status();
}

int agent_access_token(void)
{
    char url[128];
    char header[128];
    int ret;
    int retry = 0;

    if (api_token == NULL) {
        api_token = pvPortMalloc(TOKEN_SIZE);
        memset(api_token, 0, TOKEN_SIZE);
    }
#if 0
    snprintf(url, sizeof(url), "https://%s/.well-known/jwt", ES_EST_API_HOST);
    snprintf(header, sizeof(header), "User-Agent: curl/7.47.0\r\nAccept: */*");

    while(retry <= 3) {

        ret = https_get(url, header, (uint8_t *)api_token,
                        TOKEN_SIZE, tlsEDGESCALE_ROOT_CERTIFICATE_PEM);
        if (ret > 0)
            break;

        retry++;
    }
    /* set 0 at the end of the token string */
    api_token[ret] = 0;
#endif
    return 0;
}


static void feed_wdog(TimerHandle_t xTimer)
{
    BOARD_feedwdog();
    configPRINTF(("feed watchdog\r\n"));
}

void agent_task(void *pvParameters)
{
    struct queue_struct buf;

    configPRINTF(("start agent task ...\r\n"));
    //DISPLAY_MEM_USAGE

    /* check OTA status */
    check_ota_status();

    /* create a queue */
    agent_queue = xQueueCreate(AGENT_QUEUE_SIZE, MSG_SIZE);

    if (agent_init())
        goto err;

    /* subscribe the device topic */
	if (agent_sub_topic())
        goto err;

    /* create a timer to report periodically */
    report_timer = xTimerCreate("report", pdMS_TO_TICKS(PUSH_PERIOD * 1000),
                                pdTRUE, NULL, agent_report);
    xTimerStart(report_timer, pdMS_TO_TICKS(1000));

    /* feed watchdog */
    wdog_timer = xTimerCreate("wdog", pdMS_TO_TICKS(WDOG_FEED_PERIOD * 1000),
                              pdTRUE, NULL, feed_wdog);
    xTimerStart(wdog_timer, pdMS_TO_TICKS(1000));

    while(1)
    {
        memset(&buf, 0, sizeof(buf));
        if (xQueueReceive(agent_queue, &buf, pdMS_TO_TICKS(1000)) != pdFALSE) {
            process_message(buf.buf, buf.length);
        }

    }

err:
    configPRINTF(("Something error!\r\n"));
	while(1)
	{
		vTaskDelay(pdMS_TO_TICKS(1000));
	}
}
