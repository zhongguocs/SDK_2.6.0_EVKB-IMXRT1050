/*
 * Copyright (c) 2017 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>

#include "FreeRTOS.h"
#include "task.h"
#include "http_client.h"
#include "http_parser_url.h"
#include "aws_secure_sockets.h"

#define BUF_ALLOC_TIMEOUT 100

#define RC_STR(rc)	(rc == 0 ? "OK" : "ERROR")

#define HTTP_EOF           "\r\n\r\n"

#define HTTP_HOST          "Host"
#define HTTP_CONTENT_TYPE  "Content-Type"
#define HTTP_CONTENT_LEN   "Content-Length"
#define HTTP_CONT_LEN_SIZE 6

#define TMP_BUF_SIZE    2048

#define ARG_UNUSED(x) (void)(x)
#define NET_DBG(fmt, ...)
#define CONTAINER_OF(ptr, type, field) \
		    ((type *)(((char *)(ptr)) - offsetof(type, field)))

#define min(a,b) ((a) < (b) ? a : b)

static int on_header_field(struct http_parser *parser, const char *at,
			   size_t length)
{
	const char *content_len = HTTP_CONTENT_LEN;
	struct http_ctx *ctx = parser->data;
	u16_t len;

	len = strlen(content_len);
	if (length >= len && memcmp(at, content_len, len) == 0) {
		ctx->http.rsp.cl_present = true;
	}

//	print_header_field(length, at);

	return 0;
}

#define MAX_NUM_DIGITS	16

static int on_header_value(struct http_parser *parser, const char *at,
			   size_t length)
{
	char str[MAX_NUM_DIGITS];
	struct http_ctx *ctx = parser->data;

	if (ctx->http.rsp.cl_present) {
		if (length <= MAX_NUM_DIGITS - 1) {
			long int num;

			memcpy(str, at, length);
			str[length] = 0;

			num = strtol(str, NULL, 10);
			if (num == LONG_MIN || num == LONG_MAX) {
				return -EINVAL;
			}

			ctx->http.rsp.content_length = num;
		}

		ctx->http.rsp.cl_present = false;
	}

//	print_header_field(length, at);

	return 0;
}

static int on_body(struct http_parser *parser, const char *at, size_t length)
{
	struct http_ctx *ctx = parser->data;
    size_t copy_size = min(length, ctx->http.rsp.body_buf_size);

	ctx->http.rsp.body_found = 1;
    memcpy(ctx->http.rsp.body_buf + ctx->http.rsp.data_len,
           at, copy_size);
    ctx->http.rsp.data_len += copy_size;

	return 0;
}

static int http_prepare_and_send(struct http_ctx *ctx,
			  const char *payload,
			  size_t payload_len,
			  const struct sockaddr *dst,
			  void *user_send_data)
{
    memcpy(ctx->http_buf + ctx->data_len, payload, payload_len);
    ctx->data_len += payload_len;

	return 0;
}

static int _http_add_header(struct http_ctx *ctx, s32_t timeout,
			    const char *name, const char *value,
			    const struct sockaddr *dst,
			    void *user_send_data)
{
	int ret = 0;

	ret = http_prepare_and_send(ctx, name, strlen(name), dst,
				    user_send_data);
	if (value && ret >= 0) {
		ret = http_prepare_and_send(ctx, ": ", strlen(": "), dst,
					    user_send_data);
		if (ret < 0) {
			goto out;
		}

		ret = http_prepare_and_send(ctx, value, strlen(value), dst,
					    user_send_data);
		if (ret < 0) {
			goto out;
		}

		ret = http_prepare_and_send(ctx, HTTP_CRLF, strlen(HTTP_CRLF),
					    dst, user_send_data);
		if (ret < 0) {
			goto out;
		}
	}

out:
	return ret;
}

static int http_add_header(struct http_ctx *ctx, const char *field,
		    const struct sockaddr *dst,
		    void *user_send_data)
{
	return _http_add_header(ctx, ctx->timeout, field, NULL, dst,
				user_send_data);
}

static int http_add_header_field(struct http_ctx *ctx, const char *name,
			  const char *value,
			  const struct sockaddr *dst,
			  void *user_send_data)
{
	return _http_add_header(ctx, ctx->timeout, name, value, dst,
				user_send_data);
}

static int http_make_packet (struct http_ctx *ctx,
                             struct http_request *req,
				             void *user_data)
{
	const char *method = http_method_str(req->method);
	int ret = 0;

	ret = http_add_header(ctx, method, NULL, user_data);
	if (ret < 0) {
		goto out;
	}

	ret = http_add_header(ctx, " ", NULL, user_data);
	if (ret < 0) {
		goto out;
	}

	ret = http_add_header(ctx, req->url, NULL, user_data);
	if (ret < 0) {
		goto out;
	}

	ret = http_add_header(ctx, req->protocol, NULL, user_data);
	if (ret < 0) {
		goto out;
	}

	ret = http_add_header(ctx, HTTP_CRLF, NULL, user_data);
	if (ret < 0) {
		goto out;
	}

	if (req->host) {
		ret = http_add_header_field(ctx, HTTP_HOST, req->host,
					    NULL, user_data);
		if (ret < 0) {
			goto out;
		}
	}

	if (req->header_fields) {
		ret = http_add_header(ctx, req->header_fields, NULL, user_data);
		if (ret < 0) {
			goto out;
		}
	}

	if (req->content_type_value) {
		ret = http_add_header_field(ctx, HTTP_CONTENT_TYPE,
					    req->content_type_value,
					    NULL, user_data);
		if (ret < 0) {
			goto out;
		}
	}

	if (req->payload && req->payload_size) {
		char content_len_str[HTTP_CONT_LEN_SIZE];

		ret = snprintf(content_len_str, HTTP_CONT_LEN_SIZE,
			       "%u", req->payload_size);
		if (ret <= 0 || ret >= HTTP_CONT_LEN_SIZE) {
			ret = -ENOMEM;
			goto out;
		}

		ret = http_add_header_field(ctx, HTTP_CONTENT_LEN,
					    content_len_str,
					    NULL, user_data);
		if (ret < 0) {
			goto out;
		}

		ret = http_add_header(ctx, HTTP_CRLF, NULL, user_data);
		if (ret < 0) {
			goto out;
		}

		ret = http_prepare_and_send(ctx, req->payload,
					    req->payload_size,
					    NULL, user_data);
		if (ret < 0) {
			goto out;
		}
	} else {
		ret = http_add_header(ctx, HTTP_EOF, NULL, user_data);
		if (ret < 0) {
			goto out;
		}
	}

out:
	return ret;
}


/*****************************************************************/

static void http_cb_init(struct http_parser_settings *settings)
{
    settings->on_url = NULL;
    settings->on_status = NULL;
    settings->on_header_field = on_header_field;
    settings->on_header_value = on_header_value;
    settings->on_body = on_body;
}


static int http_flush(struct http_ctx *ctx)
{
    int32_t ret;

	ret = SOCKETS_Send(ctx->socket,
			( const unsigned char *) ctx->http_buf,
			ctx->data_len, 0);
	if (ret < 0 ) {
		return -1;
	}

    return ret;
}

/** http_send - send http request
 */
int http_send(struct http_ctx *ctx,
              const char *path,
              enum http_method method,
              const char *payload,
              const char *extra_header)
{
    struct http_request *req = &ctx->http_req;
    int ret;

    req->url = path;
    req->method = method;
    req->protocol = " " HTTP_PROTOCOL;

    if (extra_header)
        req->header_fields = extra_header;

    if (payload) {
        req->payload = payload;
        req->payload_size = strlen(payload);
    }

    ctx->http_buf = pvPortMalloc(TMP_BUF_SIZE);
    memset(ctx->http_buf, 0, TMP_BUF_SIZE);
    ctx->http_buf_size = TMP_BUF_SIZE;

    http_make_packet(ctx, req, NULL);

//PRINTF("\r\nhttp send:\r\n");
//PRINTF("%s\r\n", ctx->http_buf);

    ret = http_flush(ctx);
    vPortFree(ctx->http_buf);
    if (ret < 0) {
        configPRINTF(("ERR(%d): fail to send HTTP packet.", ret));
        return 0;
    }

    return ret;
}

/* http_recv - receive http packet */
// return: received bytes
int http_recv(struct http_ctx *ctx,
              uint8_t *buf, size_t size, uint32_t timeout)
{
    struct http_parser_settings *settings = &ctx->http.parser_settings;
    struct http_parser *parser = &ctx->http.parser;
	const TickType_t short_delay = pdMS_TO_TICKS(10);
	TickType_t timeout_tick = pdMS_TO_TICKS(timeout);
	TimeOut_t start_time;
    size_t recv_size;
    int ret = -1;

    ctx->http_buf = pvPortMalloc(TMP_BUF_SIZE);
    ctx->http_buf_size = TMP_BUF_SIZE;

    vTaskSetTimeOutState(&start_time);

    recv_size = min(size, ctx->http_buf_size);
    while(1) {
        ret = SOCKETS_Recv(ctx->socket, ctx->http_buf, recv_size, 0);
        if (ret > 0)
            break;

        if(xTaskCheckForTimeOut(&start_time, &timeout_tick) != pdFAIL)
        {
            ret = -1;
            break;
        }
        vTaskDelay(short_delay);
    }

    /* check if packet is received */
    if (ret < 0)
        goto err;

    ctx->data_len = ret;

    ctx->http.rsp.body_buf = buf;
    ctx->http.rsp.body_buf_size = size;
    ctx->http.rsp.body_found = 0;
    ctx->http.rsp.data_len = 0;
    parser->data = ctx;
    /* parse the http packet */
    ret = http_parser_execute(parser, settings,
                              (const char *)ctx->http_buf, ctx->data_len);
    if (ret != ctx->data_len) {
        configPRINTF(("HTTP parser error"));
        goto err;
    }

    if (parser->status_code / 100 != 2 ) {
        configPRINTF(("received HTTP error code %d", parser->status_code));
    }

    vPortFree(ctx->http_buf);
    return ctx->http.rsp.data_len;

err:
    vPortFree(ctx->http_buf);
    return -1;
}


/* http_open - connect to http server */
struct http_ctx * http_open(const char *server, int port,
                            const unsigned char *server_cert)
{
	SocketsSockaddr_t server_addr;
    struct http_request *req;
    struct http_ctx *ctx = NULL;
    int ret;

    ctx = pvPortMalloc(sizeof(struct http_ctx));
	(void)memset(ctx, 0, sizeof(struct http_ctx));

	ctx->is_init = true;
	ctx->is_client = true;

    http_parser_init(&ctx->http.parser, HTTP_RESPONSE);
    http_cb_init(&ctx->http.parser_settings);

    req = &ctx->http_req;
    req->host = server;
    req->port = port;

    /* create socket */
	ctx->socket = SOCKETS_Socket(SOCKETS_AF_INET, SOCKETS_SOCK_STREAM,
                            SOCKETS_IPPROTO_TCP);
	if (ctx->socket == SOCKETS_INVALID_SOCKET)
	{
		goto err1;
	}

    /* connect to the server */
    memset(&server_addr, 0, sizeof(server_addr));
	server_addr.ucLength = sizeof(server_addr);
	server_addr.usPort = SOCKETS_htons(port);
	server_addr.ulAddress = SOCKETS_GetHostByName(server);
	server_addr.ucSocketDomain = SOCKETS_AF_INET;

    if (server_cert) {
        /* enable TLS */
        (void) SOCKETS_SetSockOpt(ctx->socket, 0,
                SOCKETS_SO_REQUIRE_TLS, NULL, 0);
        (void) SOCKETS_SetSockOpt(ctx->socket, 0,
                SOCKETS_SO_TRUSTED_SERVER_CERTIFICATE,
                server_cert, (size_t)(strlen((const char *)server_cert) + 1));

        /* set the server name */
        (void) SOCKETS_SetSockOpt(ctx->socket, 0,
                SOCKETS_SO_SERVER_NAME_INDICATION,
                server, strlen(server));
    }

	ret = SOCKETS_Connect(ctx->socket, &server_addr,
						  (Socklen_t) sizeof(server_addr));
	if (ret < 0) {
		goto err2;
	}

    return ctx;

err2:
    SOCKETS_Close(ctx->socket);
err1:
    vPortFree(ctx);
    return NULL;
}

/* http_close - close http connection */
void http_close(struct http_ctx *ctx)
{
    SOCKETS_Close(ctx->socket);
    vPortFree((void *)ctx);
}

/**********************************************************/


int http_get(const char *url, const char *header, uint8_t *buf, size_t size)
{
    return https_get(url, header, buf, size, NULL);
}

int https_get(const char *url, const char *header,
              uint8_t *buf, size_t size, const unsigned char *server_cert)
{
    struct http_ctx *ctx = NULL;
    struct url_part *url_struct;
    int ret;

    url_struct = pvPortMalloc(sizeof(struct url_part));
    ret = parse_http_url(url, url_struct);
    if (ret) {
        goto err1;
    }

    ctx = http_open(url_struct->server, url_struct->port, server_cert);
    if (ctx == NULL) {
        configPRINTF(("error to connect server"));
        goto err1;
    }

    ret = http_send(ctx, url_struct->path, HTTP_GET, NULL, header);
    if (!ret) {
        configPRINTF(("error to send HTTP request"));
        goto err;
    }

    ret = http_recv(ctx, buf, size, 3000 /* ms */);
    if (ret < 0) {
        configPRINTF(("error to receive HTTP packet"));
        goto err;
    }

    http_close(ctx);
    vPortFree(url_struct);
    return ret;

err:
    http_close(ctx);
err1:
    vPortFree(url_struct);
    return -1;
}

int https_post(const char *url, const char *header,
               uint8_t *buf, size_t size, const unsigned char *server_cert,
               const char *payload)
{
    struct http_ctx *ctx = NULL;
    struct url_part *url_struct;
    int ret;

    url_struct = pvPortMalloc(sizeof(struct url_part));
    ret = parse_http_url(url, url_struct);
    if (ret) {
        goto err1;
    }

    ctx = http_open(url_struct->server, url_struct->port, server_cert);
    if (ctx == NULL) {
        configPRINTF(("error to connect server"));
        goto err1;
    }

    ret = http_send(ctx, url_struct->path, HTTP_POST, payload, header);
    if (!ret) {
        configPRINTF(("error to send HTTP request"));
        goto err;
    }

    ret = http_recv(ctx, buf, size, 3000 /* ms */);
    if (ret < 0) {
        configPRINTF(("error to receive HTTP packet (%d)", ret));
        goto err;
    }

    http_close(ctx);
    vPortFree(url_struct);
    return ret;

err:
    http_close(ctx);
err1:
    vPortFree(url_struct);
    return -1;
}
