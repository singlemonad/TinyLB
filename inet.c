//
// Created by tedqu on 24-9-12.
//

#include "inet.h"
#include "common.h"

#define INET_MAX_PROTOCOLS 256

static struct inet_protocol* g_inet_protocols[INET_MAX_PROTOCOLS];

int register_protocol(struct inet_protocol *proto, unsigned char protocol) {
    int ret;

    if (NULL != g_inet_protocols[protocol]) {
        return NAT_LB_EXIST;
    }

    g_inet_protocols[protocol] = proto;

    return NAT_LB_OK;
}

struct inet_protocol* get_protocol(unsigned char protocol) {
    if (NULL == g_inet_protocols[protocol]) {
        return NULL;
    }
    return g_inet_protocols[protocol];
}