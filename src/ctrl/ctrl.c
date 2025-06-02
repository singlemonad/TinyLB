//
// Created by tedqu on 25-3-5.
//

#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <rte_ether.h>
#include "../common/log.h"
#include "../common/util.h"
#include "ctrl.h"
#include "msg.pb-c.h"

// 支持通过pb接口配置的对象
// 1. svc
// 2. rs
// 3. route
// 4. acl -- 没法使用rcu更新？

static msg_handler msg_handlers[MSG_MAX][MSG_OP_MAX];

static void rcv(struct client *client) {
    ssize_t n_rcv;
    uint32_t left;

    left = client->to_rcv;
    while (left > 0) {
        if (left + client->had_rcv > DEFAULT_RCV_BUFF_SIZE) {
            RTE_LOG(ERR, EAL, "%s: Rcv buff overflow, buff max len is 1024.\n");
            goto rcv_err;
        }

        n_rcv = recv(client->fd, (char *)(client->rcv_buff + client->had_rcv), left, 0);
        if (n_rcv < 0) {
            if (errno == EAGAIN) {
                continue;
            } else {
                RTE_LOG(ERR, EAL, "%s: Rcv error, %s.\n", __func__, strerror(errno));
                goto rcv_err;
            }
        } else if (n_rcv > 0) {
            client->had_rcv += n_rcv;
            left -= n_rcv;
        } else {
            RTE_LOG(INFO, EAL, "%s: Client disconnect.\n", __func__);
            goto closed;
        }
    }

    if (left == 0) {
        return;
    }

closed:
    client->closed = true;
    return;

rcv_err:
    client->errored = true;
}

static void reset_rcv_status(struct client *client) {
    bzero(client->rcv_buff, DEFAULT_RCV_BUFF_SIZE);
    client->to_rcv = 0;
    client->had_rcv = 0;
    client->errored = false;
    client->closed = false;
}

static int handle_msg(struct client* client) {
    if (client->hdr.cfg_type > MSG_MAX || client->hdr.op_type > MSG_OP_MAX) {
        return NAT_LB_NOT_EXIST;
    }
    return msg_handlers[client->hdr.cfg_type][client->hdr.op_type](&client->hdr, client->rcv_buff);
}

static void rcv_msg(struct client* client) {
    int handle_ret;
    while (true) {
        reset_rcv_status(client);
        client->to_rcv = sizeof(struct msg_hdr);

        rcv(client);
        if (client->closed || client->errored) {
            return;
        } else {
            memcpy(&client->hdr, client->rcv_buff, client->to_rcv);
            reset_rcv_status(client);
            client->to_rcv = client->hdr.len;

            rcv(client);
            if (client->closed || client->errored) {
                return;
            } else {
                handle_ret = handle_msg(client);
                if (handle_ret != NAT_LB_OK) {
                    RTE_LOG(ERR, EAL, "%s: Handle msg failed, cfg_type=%d,op_type=%d", client->hdr.cfg_type, client->hdr.op_type);
                }
            }
        }
    }
}

void start_tcp_server(char *addr, uint16_t port) {
    int listen_fd;
    struct sockaddr_in bind_addr;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == listen_fd) {
        rte_exit(EXIT_FAILURE, "Create listen fd failed, %s", strerror(errno));
    }

    bind_addr.sin_family =AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port= htons(port);
    if (bind(listen_fd,(struct  sockaddr*)&bind_addr, sizeof(bind_addr)) == -1) {
        rte_exit(EXIT_FAILURE, "Bind failed, %s", strerror(errno));
    }

    if(listen(listen_fd,SOMAXCONN) == -1) {
        rte_exit(EXIT_FAILURE, "Listen failed, %s", strerror(errno));
    }

    while (true)
    {
        struct sockaddr_in client_addr;
        socklen_t  client_addr_len = sizeof(client_addr);
        struct client client;
        int client_fd;

        client_fd = accept(listen_fd, (struct sockaddr*)&client_addr,&client_addr_len);
        if (client_fd != -1) {
            client.fd = client_fd;
            rcv_msg(&client);

            RTE_LOG(INFO, EAL, "Handle client %d msg finished.\n", client_fd);
            close(client.fd);
        }
    }
}

void ctrl_module_init(void) {
}