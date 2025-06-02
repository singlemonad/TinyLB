//
// Created by tedqu on 25-3-5.
//

#ifndef NAT_LB_CTRL_H
#define NAT_LB_CTRL_H

#include <inttypes.h>

#define DEFAULT_RCV_BUFF_SIZE 1024

enum msg_type {
    MSG_ACL = 0,
    MSG_ROUTE,
    MSG_SVC,
    MSG_RS,
    MSG_SNAT_ADDR,
    MSG_MAX,
};

enum msg_op_type {
    MSG_OP_ADD = 0,
    MSG_OP_DEL,
    MSG_OP_MAX,
};

struct msg_hdr {
    uint32_t len;
    enum msg_type cfg_type;
    enum msg_op_type op_type;
};

struct client {
    int fd;
    struct msg_hdr hdr;
    char rcv_buff[DEFAULT_RCV_BUFF_SIZE];
    uint32_t to_rcv;
    uint32_t had_rcv;
    bool errored;
    bool closed;
};

typedef int(*msg_handler)(struct msg_hdr *hdr, void *data);

void ctrl_module_init(void);
void start_tcp_server(char *addr, uint16_t port);

#endif //NAT_LB_CTRL_H
