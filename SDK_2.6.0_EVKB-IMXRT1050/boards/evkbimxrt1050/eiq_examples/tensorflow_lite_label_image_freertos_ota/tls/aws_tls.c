/*
 * Amazon FreeRTOS TLS V1.1.0
 * Copyright (C) 2017 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "FreeRTOSIPConfig.h"
#include "aws_tls.h"
#include "aws_crypto.h"
#include "task.h"
#include "eds_credential.h"

/* mbedTLS includes. */
#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/debug.h"

/* C runtime includes. */
#include <string.h>
#include <time.h>
#include <stdio.h>

#include "fsl_trng.h"

/**
 * @brief Internal context structure.
 *
 * @param[in] pcDestination Server location, can be a DNS name or IP address.
 * @param[in] pcServerCertificate Server X.509 certificate in PEM format to trust.
 * @param[in] ulServerCertificateLength Length in bytes of the server certificate.
 * @param[in] pxNetworkRecv Callback for receiving data on an open TCP socket.
 * @param[in] pxNetworkSend Callback for sending data on an open TCP socket.
 * @param[in] pvCallerContext Opaque pointer provided by caller for above callbacks.
 * @param[out] mbedSslCtx Connection context for mbedTLS.
 * @param[out] mbedSslConfig Configuration context for mbedTLS.
 * @param[out] mbedX509CA Server certificate context for mbedTLS.
 * @param[out] mbedX509Cli Client certificate context for mbedTLS.
 * @param[out] mbedPkAltCtx RSA crypto implementation context for mbedTLS.
 * @param[out] pxP11FunctionList PKCS#11 function list structure.
 * @param[out] xP11Session PKCS#11 session context.
 * @param[out] xP11PrivateKey PKCS#11 private key context.
 * @param[out] ulP11ModulusBytes Number of bytes in the client private key modulus.
 */
typedef struct TLSContext
{
    const char * pcDestination;
    const char * pcServerCertificate;
    uint32_t ulServerCertificateLength;
    const char ** ppcAlpnProtocols;
    uint32_t ulAlpnProtocolsCount;

    NetworkRecv_t pxNetworkRecv;
    NetworkSend_t pxNetworkSend;
    void * pvCallerContext;

    /* mbedTLS. */
    mbedtls_ssl_context mbedSslCtx;
    mbedtls_ssl_config mbedSslConfig;
    mbedtls_x509_crt mbedX509CA;
    mbedtls_x509_crt mbedX509Cli;
    mbedtls_pk_context mbedPkCtx;

    mbedtls_entropy_context mbedEntropy;
    mbedtls_ctr_drbg_context mbedDrbg;
} TLSContext_t;

/*
 * Helper routines.
 */

/**
 * @brief Network send callback shim.
 *
 * @param[in] pvContext Caller context.
 * @param[in] pucData Byte buffer to send.
 * @param[in] xDataLength Length of byte buffer to send.
 *
 * @return Number of bytes sent, or a negative value on error.
 */
static int prvNetworkSend( void * pvContext,
                           const unsigned char * pucData,
                           size_t xDataLength )
{
    TLSContext_t * pCtx = ( TLSContext_t * ) pvContext; /*lint !e9087 !e9079 Allow casting void* to other types. */

    return ( int ) pCtx->pxNetworkSend( pCtx->pvCallerContext, pucData, xDataLength );
}

/**
 * @brief Network receive callback shim.
 *
 * @param[in] pvContext Caller context.
 * @param[out] pucReceiveBuffer Byte buffer to receive into.
 * @param[in] xReceiveLength Length of byte buffer for receive.
 *
 * @return Number of bytes received, or a negative value on error.
 */
static int prvNetworkRecv( void * pvContext,
                           unsigned char * pucReceiveBuffer,
                           size_t xReceiveLength )
{
    TLSContext_t * pCtx = ( TLSContext_t * ) pvContext; /*lint !e9087 !e9079 Allow casting void* to other types. */

    return ( int ) pCtx->pxNetworkRecv( pCtx->pvCallerContext, pucReceiveBuffer, xReceiveLength );
}

/**
 * @brief Helper for setting up potentially hardware-based cryptographic context
 * for the client TLS certificate and private key.
 *
 * @param Caller context.
 *
 * @return Zero on success.
 */
static int prvInitializeClientCredential(TLSContext_t * pCtx)
{
    int ret = 0;

    mbedtls_pk_init(&pCtx->mbedPkCtx);
    mbedtls_x509_crt_init(&pCtx->mbedX509Cli);

    ret = mbedtls_pk_parse_key(&pCtx->mbedPkCtx, tlsDEVICE_PRIVATE_PEM,
                               tlsDEVICE_PRIVATE_SIZE, NULL, 0);
    if (ret)
        goto err;

    ret = mbedtls_x509_crt_parse(&pCtx->mbedX509Cli,
                                 tlsDEVICE_CERTIFICATE_PEM,
                                 tlsDEVICE_CERTIFICATE_SIZE);
    if (ret)
        goto err;

    ret = mbedtls_ssl_conf_own_cert(&pCtx->mbedSslConfig,
                                    &pCtx->mbedX509Cli, &pCtx->mbedPkCtx);
    if (ret)
        goto err;

err:
    return ret;
}

/*
 * Interface routines.
 */

BaseType_t TLS_Init( void ** ppvContext,
                     TLSParams_t * pxParams )
{
    BaseType_t xResult = 0;
    TLSContext_t * pCtx = NULL;

    /* Allocate an internal context. */
    pCtx = ( TLSContext_t * ) pvPortMalloc( sizeof( TLSContext_t ) ); /*lint !e9087 !e9079 Allow casting void* to other types. */

    if( NULL != pCtx )
    {
        memset( pCtx, 0, sizeof( TLSContext_t ) );
        *ppvContext = pCtx;

        /* Initialize the context. */
        pCtx->pcDestination = pxParams->pcDestination;
        pCtx->pcServerCertificate = pxParams->pcServerCertificate;
        pCtx->ulServerCertificateLength = pxParams->ulServerCertificateLength;
        pCtx->ppcAlpnProtocols = pxParams->ppcAlpnProtocols;
        pCtx->ulAlpnProtocolsCount = pxParams->ulAlpnProtocolsCount;
        pCtx->pxNetworkRecv = pxParams->pxNetworkRecv;
        pCtx->pxNetworkSend = pxParams->pxNetworkSend;
        pCtx->pvCallerContext = pxParams->pvCallerContext;
    }

    return xResult;
}

/*-----------------------------------------------------------*/
#ifdef MBEDTLS_DEBUG_C
static void ssl_dbg_output(void *ctx, int level, const char *file,
                                    int line, const char *str)
{
    PRINTF("%s:%d: %s\r\n", file, line, str);
    return;
}
#endif

BaseType_t TLS_Connect( void * pvContext )
{
    BaseType_t xResult = 0;
    TLSContext_t * pCtx = ( TLSContext_t * ) pvContext; /*lint !e9087 !e9079 Allow casting void* to other types. */

    /* Ensure that the FreeRTOS heap is used. */
    CRYPTO_ConfigureHeap();

    /* Initialize mbedTLS structures. */
    mbedtls_ssl_init( &pCtx->mbedSslCtx );
    mbedtls_ssl_config_init( &pCtx->mbedSslConfig );
    mbedtls_x509_crt_init( &pCtx->mbedX509CA );

    memset(&pCtx->mbedEntropy, 0, sizeof(pCtx->mbedEntropy));
    mbedtls_entropy_init(&pCtx->mbedEntropy);

    mbedtls_ctr_drbg_init(&pCtx->mbedDrbg);
    mbedtls_ctr_drbg_seed(&pCtx->mbedDrbg, mbedtls_entropy_func,
                    &pCtx->mbedEntropy, NULL, 0);

    /* Decode the root certificate: either the default or the override. */
    if( NULL != pCtx->pcServerCertificate )
    {
        xResult = mbedtls_x509_crt_parse( &pCtx->mbedX509CA,
                                          ( const unsigned char * ) pCtx->pcServerCertificate,
                                          pCtx->ulServerCertificateLength );
    }

    /* Start with protocol defaults. */
    if( 0 == xResult )
    {
        xResult = mbedtls_ssl_config_defaults( &pCtx->mbedSslConfig,
                                               MBEDTLS_SSL_IS_CLIENT,
                                               MBEDTLS_SSL_TRANSPORT_STREAM,
                                               MBEDTLS_SSL_PRESET_DEFAULT );
    }

    if( 0 == xResult )
    {
        /* Server certificate validation is mandatory. */
        mbedtls_ssl_conf_authmode( &pCtx->mbedSslConfig, MBEDTLS_SSL_VERIFY_REQUIRED );

        /* Set the RNG callback. */
        mbedtls_ssl_conf_rng(&pCtx->mbedSslConfig,
                             mbedtls_ctr_drbg_random,
                             &pCtx->mbedDrbg);

        /* Set issuer certificate. */
        mbedtls_ssl_conf_ca_chain( &pCtx->mbedSslConfig, &pCtx->mbedX509CA, NULL );

        /* Setup the client credential. */
        xResult = prvInitializeClientCredential( pCtx );
    }

    if( 0 == xResult && NULL != pCtx->ppcAlpnProtocols )
    {
        /* Include an application protocol list in the TLS ClientHello 
         * message. */
        xResult = mbedtls_ssl_conf_alpn_protocols( 
            &pCtx->mbedSslConfig, 
            pCtx->ppcAlpnProtocols );
    }

    if( 0 == xResult )
    {
        /* Set the resulting protocol configuration. */
        xResult = mbedtls_ssl_setup( &pCtx->mbedSslCtx, &pCtx->mbedSslConfig );
    }

#ifdef MBEDTLS_DEBUG_C
    mbedtls_ssl_conf_dbg(&pCtx->mbedSslConfig, ssl_dbg_output, NULL);
    mbedtls_debug_set_threshold(4);
#endif

    /* Set the hostname, if requested. */
    if( ( 0 == xResult ) && ( NULL != pCtx->pcDestination ) )
    {
        xResult = mbedtls_ssl_set_hostname( &pCtx->mbedSslCtx, pCtx->pcDestination );
    }

    /* Set the socket callbacks. */
    if( 0 == xResult )
    {
        mbedtls_ssl_set_bio( &pCtx->mbedSslCtx,
                             pCtx,
                             prvNetworkSend,
                             prvNetworkRecv,
                             NULL );

        /* Negotiate. */
        while( 0 != ( xResult = mbedtls_ssl_handshake( &pCtx->mbedSslCtx ) ) )
        {
            if( ( MBEDTLS_ERR_SSL_WANT_READ != xResult ) &&
                ( MBEDTLS_ERR_SSL_WANT_WRITE != xResult ) )
            {
                break;
            }
        }
    }

    /* Free up allocated memory. */
    mbedtls_x509_crt_free( &pCtx->mbedX509CA );
    mbedtls_x509_crt_free( &pCtx->mbedX509Cli );

    return xResult;
}

/*-----------------------------------------------------------*/

BaseType_t TLS_Recv( void * pvContext,
                     unsigned char * pucReadBuffer,
                     size_t xReadLength )
{
    BaseType_t xResult = 0;
    TLSContext_t * pCtx = ( TLSContext_t * ) pvContext; /*lint !e9087 !e9079 Allow casting void* to other types. */
    size_t xRead = 0;

    if( NULL != pCtx )
    {
        while( xRead < xReadLength )
        {
            xResult = mbedtls_ssl_read( &pCtx->mbedSslCtx,
                                        pucReadBuffer + xRead,
                                        xReadLength - xRead );

            if( 0 < xResult )
            {
                /* Got data, so update the tally and keep looping. */
                xRead += ( size_t ) xResult;
            }
            else
            {
                if( ( 0 == xResult ) || ( MBEDTLS_ERR_SSL_WANT_READ != xResult ) )
                {
                    /* No data and no error or call read again, if indicated, otherwise return error. */
                    break;
                }
            }
        }
    }

    if( 0 <= xResult )
    {
        xResult = ( BaseType_t ) xRead;
    }

    return xResult;
}

/*-----------------------------------------------------------*/

BaseType_t TLS_Send( void * pvContext,
                     const unsigned char * pucMsg,
                     size_t xMsgLength )
{
    BaseType_t xResult = 0;
    TLSContext_t * pCtx = ( TLSContext_t * ) pvContext; /*lint !e9087 !e9079 Allow casting void* to other types. */
    size_t xWritten = 0;

    if( NULL != pCtx )
    {
        while( xWritten < xMsgLength )
        {
            xResult = mbedtls_ssl_write( &pCtx->mbedSslCtx,
                                         pucMsg + xWritten,
                                         xMsgLength - xWritten );

            if( 0 < xResult )
            {
                /* Sent data, so update the tally and keep looping. */
                xWritten += ( size_t ) xResult;
            }
            else
            {
                if( ( 0 == xResult ) || ( MBEDTLS_ERR_SSL_WANT_WRITE != xResult ) )
                {
                    /* No data and no error or call read again, if indicated, otherwise return error. */
                    break;
                }
            }
        }
    }

    if( 0 <= xResult )
    {
        xResult = ( BaseType_t ) xWritten;
    }

    return xResult;
}

/*-----------------------------------------------------------*/

void TLS_Cleanup( void * pvContext )
{
    TLSContext_t * pCtx = ( TLSContext_t * ) pvContext; /*lint !e9087 !e9079 Allow casting void* to other types. */

    if( NULL != pCtx )
    {
        /* Cleanup mbedTLS. */
        mbedtls_ssl_close_notify( &pCtx->mbedSslCtx ); /*lint !e534 The error is already taken care of inside mbedtls_ssl_close_notify*/
        mbedtls_ssl_free( &pCtx->mbedSslCtx );
        mbedtls_ssl_config_free( &pCtx->mbedSslConfig );

        mbedtls_pk_free(&pCtx->mbedPkCtx);
        mbedtls_entropy_free(&pCtx->mbedEntropy);
        mbedtls_ctr_drbg_free(&pCtx->mbedDrbg);

        /* Free memory. */
        vPortFree( pCtx );
    }
}
