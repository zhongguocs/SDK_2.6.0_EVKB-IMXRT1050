
#ifndef _EDGESCALE_AGENT_H
#define _EDGESCALE_AGENT_H


#define AGENT_OTA_START     "ota-start"
#define AGENT_OTA_FETCH     "ota-fetch"
#define AGENT_OTA_VERIFY    "ota-verify"
#define AGENT_OTA_INSTALL   "ota-install"
#define AGENT_OTA_REBOOT    "ota-reboot"
#define AGENT_OTA_COMPLETE  "ota-complete"

/* the access token for http api */
#define TOKEN_SIZE     384

extern char *api_token;

extern int do_ota(char *image_url, char *mid);
extern int ota_status_report(char *status, char *mid, char *token);
extern void check_ota_status(void);
extern int agent_access_token(void);

#endif /* _EDGESCALE_AGENT_H */
