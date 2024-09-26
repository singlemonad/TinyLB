//
// Created by tedqu on 24-9-10.
//

#include "ipv4_out.h"
#include "ipv4_forward.h"

int ipv4_forward(sk_buff_t *skb) {
    return ipv4_output(skb);
}