
#ifndef _HTTP_HTTP_CLIENT_H_
#define _HTTP_HTTP_CLIENT_H_

#include "http_type.h"
#include "http_parser.h"
#include "aws_secure_sockets.h"

#define HTTP_PROTOCOL	   "HTTP/1.1"
#define HTTP_CRLF "\r\n"

struct http_ctx;

enum http_final_call {
	HTTP_DATA_MORE = 0,
	HTTP_DATA_FINAL = 1,
};

enum http_state {
	  HTTP_STATE_CLOSED,
	  HTTP_STATE_WAITING_HEADER,
	  HTTP_STATE_RECEIVING_HEADER,
	  HTTP_STATE_HEADER_RECEIVED,
	  HTTP_STATE_OPEN,
};

/**
 * HTTP client request. This contains all the data that is needed when doing
 * a HTTP request.
 */
struct http_request {
	/** The HTTP method: GET, HEAD, OPTIONS, POST, ... */
	enum http_method method;

	/** The URL for this request, for example: /index.html */
	const char *url;

	/** The HTTP protocol: HTTP/1.1 */
	const char *protocol;

	/** The HTTP header fields (application specific)
	 * The Content-Type may be specified here or in the next field.
	 * Depending on your application, the Content-Type may vary, however
	 * some header fields may remain constant through the application's
	 * life cycle.
	 */
	const char *header_fields;

	/** The value of the Content-Type header field, may be NULL */
	const char *content_type_value;

	/** Hostname to be used in the request */
	const char *host;

	u16_t port;

	/** Payload, may be NULL */
	const char *payload;

	/** Payload size, may be 0 */
	u16_t payload_size;

	u8_t https:1;

	/* CA certificate in PEM */
	char *ca;
	uint32_t ca_len;
};

/**
 * Http context information. This contains all the data that is
 * needed when working with http API.
 */
struct http_ctx {
	/* socket */
	Socket_t socket;

	/** Original server address */
	struct sockaddr *server_addr;

    u8_t *http_buf;
    size_t http_buf_size;

    /** Length of the data in http_buf. */
    size_t data_len;



    struct http_request http_req;

	struct {
		/** HTTP response information */
		struct {
			/** Where the body starts.
			 */
			u8_t *body_buf;
            size_t body_buf_size;

			/** Length of the data in the result buf. If the value
			 * is larger than response_buf_len, then it means that
			 * the data is truncated and could not be fully copied
			 * into response_buf. This can only happen if the user
			 * did not set the response callback. If the callback
			 * is set, then the HTTP client API will call response
			 * callback many times so that all the data is
			 * delivered to the user.
			 */
			size_t data_len;

			/** HTTP Content-Length field value */
			size_t content_length;

			/** Content length parsed. This should be the same as
			 * the content_length field if parsing was ok.
			 */
			size_t processed;

			/* https://tools.ietf.org/html/rfc7230#section-3.1.2
			 * The status-code element is a 3-digit integer code
			 *
			 * The reason-phrase element exists for the sole
			 * purpose of providing a textual description
			 * associated with the numeric status code. A client
			 * SHOULD ignore the reason-phrase content.
			 */
//			char http_status[HTTP_STATUS_STR_SIZE];

			u8_t cl_present:1;
			u8_t body_found:1;
			u8_t message_complete:1;
		} rsp;

		/** HTTP parser for parsing the initial request */
		struct http_parser parser;

		/** HTTP parser settings */
		struct http_parser_settings parser_settings;

		/** HTTP Request URL */
		char *url;

		/** URL's length */
		u16_t url_len;
	} http;

	/** User specified data that is passed in callbacks. */
	u8_t *user_data;

	/** State of the websocket */
	enum http_state state;

	/** Network buffer allocation timeout */
	s32_t timeout;

	/** Is this context setup or not */
	u8_t is_init : 1;

	/** Is this context setup for client or server */
	u8_t is_client : 1;

	/** Is this instance supporting TLS or not. */
	u8_t is_tls : 1;

	/** Are we connected or not (only used in client) */
	u8_t is_connected : 1;
};

int http_send(struct http_ctx *ctx,
              const char *path,
              enum http_method method,
              const char *payload,
              const char *extra_header);
int http_recv(struct http_ctx *ctx,
              uint8_t *buf, size_t size, uint32_t timeout);

struct http_ctx * http_open(const char *server, const int port,
                            const unsigned char *server_cert);
void http_close(struct http_ctx *ctx);

int https_get(const char *url, const char *header,
              uint8_t *buf, size_t size, const unsigned char *server_cert);

int https_post(const char *url, const char *header,
               uint8_t *buf, size_t size, const unsigned char *server_cert,
               const char *payload);
#endif
