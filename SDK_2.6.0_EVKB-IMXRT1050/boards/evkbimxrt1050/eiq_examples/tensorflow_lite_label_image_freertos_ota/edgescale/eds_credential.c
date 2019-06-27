
#include <string.h>
#include <stdio.h>

#include "eds_config.h"

const unsigned char tlsEDGESCALE_ROOT_CERTIFICATE_PEM[] =
                            EDGESCALE_ROOT_CERTIFICATE_PEM;

const size_t tlsEDGESCALE_ROOT_CERTIFICATE_SIZE =
                            sizeof(tlsEDGESCALE_ROOT_CERTIFICATE_PEM);

const unsigned char tlsDEVICE_CERTIFICATE_PEM[] = EDS_DEVICE_CERT_PEM;

const size_t tlsDEVICE_CERTIFICATE_SIZE =
                            sizeof(tlsDEVICE_CERTIFICATE_PEM);

const unsigned char tlsDEVICE_PRIVATE_PEM[] = EDS_DEVICE_PRIVATE_PEM;

const size_t tlsDEVICE_PRIVATE_SIZE = sizeof(tlsDEVICE_PRIVATE_PEM);

const unsigned char tlsAWS_SERVER_CA_1B[] = AWS_SERVER_CA_1B_PEM;
