/*
 * Copyright (C) 2018 Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <string.h>

#include "hal_itls.h"

#define DEBUG_LEVEL     1

#if defined(ON_DAILY)
#define PRODUCT_KEY     "a1V2WSinkfc"
#define PRODUCT_SECRET  "i11xxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
#else
#define PRODUCT_KEY     "a1WO4Z9qHRw"
#define PRODUCT_SECRET  "i113xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
#endif

extern int itls_client_sample(
           char *product_key, char *product_secret, int debug_level);
extern int idtls_client_sample(
           char *product_key, char *product_secret, int debug_level);

int main(int argc, char *argv[])
{
    int ret;

    printf("===========> iTLS Client Sample start.\n");
    ret = itls_client_sample(
               PRODUCT_KEY, PRODUCT_SECRET, DEBUG_LEVEL);
    if (ret < 0) {
        printf("iTLS Client Sample Failed!\n");
        return -1;
    }
    printf("<=========== iTLS Client Sample End.\n\n");

#if defined(CONFIG_SSL_DTLS)
    printf("===========> iDTLS Client Sample start.\n");
    ret = idtls_client_sample(
               PRODUCT_KEY, PRODUCT_SECRET, DEBUG_LEVEL);
    if (ret < 0) {
        printf("iDTLS Client Sample Test Failed!\n");
        return -1;
    }
    printf("<=========== iDTLS Client Sample End.\n\n");
#endif

    return 0;
}

