//
// Created by tedqu on 24-11-20.
//

#ifndef NAT_LB_LB_H
#define NAT_LB_LB_H

#ifdef __cplusplus
extern "C" {
#endif

struct wrr_sch_data {
    struct rs* cl;
    int cw;
    int mw;
    int di;
};

extern void wrr_init(void);
void lb_module_init(void);

#endif //NAT_LB_LB_H
