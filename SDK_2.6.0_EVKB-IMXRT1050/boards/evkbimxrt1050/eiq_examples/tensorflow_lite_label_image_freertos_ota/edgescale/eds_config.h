
#ifndef __EDGESCALE_EDS_CONFIG_H
#define __EDGESCALE_EDS_CONFIG_H

/* the version of the edgescale agent */
#define AGENT_VERSION   "1.3.3-d5"

/* MQTT */
#define MQTT_SERVER      "int.msg.edgescale.org"
#define MQTT_PORT        443
/* client ID */
#define CLIENT_ID  "bad10e144b335d1f9edd0bcfd7756920.iot.generic.imxrt.nxp"

#define ES_API_HOST      "api.edgescale.org"
#define ES_EST_API_HOST  "int.e-est.edgescale.org"

/* device certificate in PEM format */
#define EDS_DEVICE_CERT_PEM                                        \
"-----BEGIN CERTIFICATE-----\n"                                    \
"MIID9DCCAtygAwIBAgIRAOuopKVZo4Y3zVI2JbBNfn0wDQYJKoZIhvcNAQELBQAw" \
"GzEZMBcGA1UEAwwQTlhQIEVkZ2VTY2FsZSBDQTAeFw0xOTA2MjUwNzEyNTJaFw0y" \
"MDA2MjQwNzEyNTJaMIGJMQ4wDAYDVQQGEwVDaGluYTEQMA4GA1UECBMHYkVJSklO" \
"RzELMAkGA1UEBxMCYmoxCjAIBgNVBAoTAVgxCzAJBgNVBAsTAkROMT8wPQYDVQQD" \
"EzZiYWQxMGUxNDRiMzM1ZDFmOWVkZDBiY2ZkNzc1NjkyMC5pb3QuZ2VuZXJpYy5p" \
"bXhydC5ueHAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9IhkXuwHD" \
"6krWOn1jUoYRmL4BpRBFqu482kE6WMBGBxNvxaL4KVq63B9XCsh2jvywC94aqNXb" \
"xZJiwSJbt/v3pRedNZbeDLaYiu35v8V+8u1lm0mZmUMqtUG/q9PycrJSAu+oYRro" \
"bA2iP3WXQw5AO/ac54iwSJRDPcWyPxcBSMezKicbciQ/Oa9NS5mQAeuiFB3h0kK6" \
"DY0OP/tzzHHozQSh33yEBACAHjBz+ZHKSYlXQCUsM8TuDz+McoXPA38sJynH38Z7" \
"Zm5AdfuSYa9AZqT2TBdCEwJtoDxksr4KQ+HylekznTWWi0+3RKbfjoE6wMGQTrId" \
"7zLD7XFqFgDDAgMBAAGjgcMwgcAwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSG" \
"alF8X5vKt0o55rpiRdwsUuPNyzBMBggrBgEFBQcBAQRAMD4wPAYIKwYBBQUHMAGG" \
"MGh0dHBzOi8vaW50LmUtZXN0LmVkZ2VzY2FsZS5vcmcvLndlbGwta25vd24vb2Nz" \
"cDBBBgNVHR8EOjA4MDagNKAyhjBodHRwczovL2ludC5lLWVzdC5lZGdlc2NhbGUu" \
"b3JnLy53ZWxsLWtub3duL29jc3AwDQYJKoZIhvcNAQELBQADggEBAJQcYUMN2lE9" \
"PqWqCFUiK9fX/08Fapt8WrEVmDWnG+QEzpObaSW7TGyZ2XxNIHc5i+LB/Rq/WIlj" \
"NiOGI6+nI0dyhuS7/mjCE2tkdgb8vl45UO8vd4UNoEC1eSwsSnj081oZju+SaPEk" \
"f/BsDaPJ0EKUUraz6g2MEJ4C1qLp+T/utBrky1rrTsmwpPrl1ROxAI7ejeZP57pS" \
"ksF9BWvR935GvirMkyAMcE/3LJrCb/4qWUs7Mji8rWZFmzufSym2OeBQDIi1pC5i" \
"QYiKNn4jTO0ZelBiDNuOUf4VQeFaLwWMlJB49gh5DcOqYGUEG9wtxwM42d/FRTrn" \
"lMzSw0qmUWE="                                                   \
"-----END CERTIFICATE-----\n"

/* device private key in PEM format */
#define EDS_DEVICE_PRIVATE_PEM                                     \
"-----BEGIN RSA PRIVATE KEY-----\n"                                \
"MIIEpAIBAAKCAQEAvSIZF7sBw+pK1jp9Y1KGEZi+AaUQRaruPNpBOljARgcTb8Wi" \
"+ClautwfVwrIdo78sAveGqjV28WSYsEiW7f796UXnTWW3gy2mIrt+b/FfvLtZZtJ" \
"mZlDKrVBv6vT8nKyUgLvqGEa6GwNoj91l0MOQDv2nOeIsEiUQz3Fsj8XAUjHsyon" \
"G3IkPzmvTUuZkAHrohQd4dJCug2NDj/7c8xx6M0Eod98hAQAgB4wc/mRykmJV0Al" \
"LDPE7g8/jHKFzwN/LCcpx9/Ge2ZuQHX7kmGvQGak9kwXQhMCbaA8ZLK+CkPh8pXp" \
"M501lotPt0Sm346BOsDBkE6yHe8yw+1xahYAwwIDAQABAoIBAC9qUvweB+1D2Ysn" \
"krPJxo62yjvDU/cDSUK8PMoR4fIsZ/UHiTnJtFNQSBMcQvFmG3dPIllwply4hWB4" \
"ptJzp5mILAlfm/kDGuvXOJ36M9sFr/pfGe6F+87DLj6NJ0+K7aWd0tNVtNc775cT" \
"bbmEOBhmcAcaDKyVJYZOADgVlQDe/M5TxVufxDVPtatzL9VlxtMtkfCR9xjbH1W2" \
"ukJuvwtJVY5otQNlsONl+1gp5KP4ltmYY8C6qvFjXWjwGAjg45jwdr10f1R9dTZz" \
"Hz5gHBOweE2kEQ8/bks6KBPwf2liTwUrVr1pa29D+io7mMEWl9WhicfbVQGV0Zl9" \
"sq/0scECgYEA+6noKmRAu3/XQiukDevkOPYBq5M38K4Y+ZcoYeCKl/OLKpK5KaSr" \
"LOT21Bq6NgFNYgs16HXwj+vBPdTLudSRhfYNXkOugKqPkpjeWDXmqKFbhqkgAd9D" \
"/mVbdEdLn6RQKGSDlLpR4wY4E2jGd5ky4fdEMndg/GQAUD0TPda1ThMCgYEAwGRe" \
"MbOHi4IWz45GDJUaDGfB964uATrCDwLy1ByLJ119a99fnAJc15PxEGdAV9xZUQ1K" \
"YTeMmZHNosqrHPxU7DAl1CZPzLvqvozhf4BD5HBqcdC0ENjQPPyzS3acsnv9AUSd" \
"sKwGONgSBXUTaBLLS07u109yEyMf+oBhqYABGJECgYBUsRYvhfN+5gPkAdnA0ZzJ" \
"Soi/W9jch0piXGs7nRwnDM/NsPjdOcxdXGRwdtopqICJOSqYI3CkjntGuqEg1Zdv" \
"lKFlErPcGwocFJPm7aTFJSAvDiV2W9N+/k8rr36Up/BN152sZJOAKiye44i+4PCN" \
"uO/bZ+9coK62UgdyrRnwvwKBgQCpfcKd9pOLC+gcojKEEzcHhsES+pf87U7Y+rgC" \
"tcLBw1MjHX6Val9wbB0LXmsI/E6TYSoNy2pKQHDw4asttf76tNAevkG/FC4SAPsH" \
"4G/vaDneWwbHcLrDf7xU1wHlG+Ygn9psMqCoo3H87M9T+HqwtbEkbhEJWwBpJ4Di" \
"WqqcgQKBgQDBXm1Vyx1ROuET9To56lgKjYuhs+WRj/XQlu10IEvLgeAjRrtK/cRS" \
"OjVwkei1fhkmzxS539k5ewKvXIjCqqTqj4iKPkK6tf/hAWTCI3+5i4jOfSyanNUu" \
"Rtlenfs2qqmTktQ8o9N6E30gUVRqzTw2m91FytQvbimNFfmzTe89NA=="       \
"-----END RSA PRIVATE KEY-----\n"


/* CN=NXP EdgeScale CA */
#define EDGESCALE_ROOT_CERTIFICATE_PEM                             \
"-----BEGIN CERTIFICATE-----\n"                                    \
"MIIDCTCCAfGgAwIBAgIJALPMA30cAFhtMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV" \
"BAMMEE5YUCBFZGdlU2NhbGUgQ0EwHhcNMTcxMjA3MDkwNjEwWhcNMjcxMjA1MDkw" \
"NjEwWjAbMRkwFwYDVQQDDBBOWFAgRWRnZVNjYWxlIENBMIIBIjANBgkqhkiG9w0B" \
"AQEFAAOCAQ8AMIIBCgKCAQEAxdf81Q3TWcPMuAZ6RrYk8vUDcPlyxRv31mxQCroL" \
"+BJXsjXYdbie3kQuLdFEm36bKmwQOA/qoYwH+avo78aoi6bAfEtzTpO0o5ckilNk" \
"Wan1C1uIsV0TKy7GHC/Bai4Pf/AHzPMT03IA1gvVNPXNoXzZ6d8RZ09WjDMnQyg6" \
"C7Oz/gU2XiX+jVKWiCPmdzB6StudPfWvEFCIFZLBMiL8uFMir895a/z/IvrbwQfY" \
"yuln/Ek6vMdxdDSXwJPSfytbeXovBicqnCmNQx+8rkXfOMm3gGTSMlsxUsEgNHHj" \
"Kv2bbaOw2gBoPNm16B1SjsHCCPSgxBmzNU9/Ni+PHZqfGQIDAQABo1AwTjAdBgNV" \
"HQ4EFgQUhmpRfF+byrdKOea6YkXcLFLjzcswHwYDVR0jBBgwFoAUhmpRfF+byrdK" \
"Oea6YkXcLFLjzcswDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAHWIn" \
"+9nOLXYeW9lEmHkNkAatPlidz4/lhaFc2zhM1AYp8UZVxe2bOOgIAJMrBnpgp2NG" \
"7wJUBfN2ZasLFkqv+u2iFwj8ulbe0QIdduDfQAbBurxakArMeNnQA15M3wtaU3Z9" \
"RXk/wQPPd73yAYWbYvcfCAl+bLGKXdRm5F1Tbv/Brq1VbHuCNGG2POo7+rK5i4QY" \
"y+57QrSeMHNiJ1O2ZQarrBl4ic+2FbuYEsC0UJAupIZPb6+XhmvLeb/RBhX9pr5E" \
"AspHXGj6WL0VWjokq/Qr0EMP9PKJ9ylOfmISLC1Bs4QcYk6l4SYN92TVySpmQg7i" \
"EnCghI8G0Xu0s81yew=="                                             \
"-----END CERTIFICATE-----\n";

/* C = US, O = Amazon, OU = Server CA 1B, CN = Amazon */
#define AWS_SERVER_CA_1B_PEM                                       \
"-----BEGIN CERTIFICATE-----\n"                                    \
"MIIESTCCAzGgAwIBAgITBn+UV4WH6Kx33rJTMlu8mYtWDTANBgkqhkiG9w0BAQsF" \
"ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6" \
"b24gUm9vdCBDQSAxMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL" \
"MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB" \
"IDFCMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK" \
"AoIBAQDCThZn3c68asg3Wuw6MLAd5tES6BIoSMzoKcG5blPVo+sDORrMd4f2AbnZ" \
"cMzPa43j4wNxhplty6aUKk4T1qe9BOwKFjwK6zmxxLVYo7bHViXsPlJ6qOMpFge5" \
"blDP+18x+B26A0piiQOuPkfyDyeR4xQghfj66Yo19V+emU3nazfvpFA+ROz6WoVm" \
"B5x+F2pV8xeKNR7u6azDdU5YVX1TawprmxRC1+WsAYmz6qP+z8ArDITC2FMVy2fw" \
"0IjKOtEXc/VfmtTFch5+AfGYMGMqqvJ6LcXiAhqG5TI+Dr0RtM88k+8XUBCeQ8IG" \
"KuANaL7TiItKZYxK1MMuTJtV9IblAgMBAAGjggE7MIIBNzASBgNVHRMBAf8ECDAG" \
"AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUWaRmBlKge5WSPKOUByeW" \
"dFv5PdAwHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUH" \
"AQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRy" \
"dXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5yb290Y2ExLmFtYXpvbnRy" \
"dXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js" \
"LnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBMGA1UdIAQMMAow" \
"CAYGZ4EMAQIBMA0GCSqGSIb3DQEBCwUAA4IBAQCFkr41u3nPo4FCHOTjY3NTOVI1" \
"59Gt/a6ZiqyJEi+752+a1U5y6iAwYfmXss2lJwJFqMp2PphKg5625kXg8kP2CN5t" \
"6G7bMQcT8C8xDZNtYTd7WPD8UZiRKAJPBXa30/AbwuZe0GaFEQ8ugcYQgSn+IGBI" \
"8/LwhBNTZTUVEWuCUUBVV18YtbAiPq3yXqMB48Oz+ctBWuZSkbvkNodPLamkB2g1" \
"upRyzQ7qDn1X8nn8N8V7YJ6y68AtkHcNSRAnpTitxBKjtKPISLMVCx7i4hncxHZS" \
"yLyKQXhw2W2Xs0qLeC1etA+jTGDK4UfLeC0SF7FSi8o5LL21L8IzApar2pR/"     \
"-----END CERTIFICATE-----\n";

#endif /* __EDGESCALE_EDS_CONFIG_H */