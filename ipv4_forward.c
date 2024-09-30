//
// Created by tedqu on 24-9-10.
//

#include "ipv4_out.h"
#include "ipv4_forward.h"

int ipv4_forward(sk_buff_t *skb, sk_ext_info_t *ext) {
    return ipv4_output(skb, ext);
}