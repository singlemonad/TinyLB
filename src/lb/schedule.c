//
// Created by tedqu on 25-5-27.
//

#include "schedule.h"

struct scheduler scheduler_array[SCHEDULER_TYPE_MAX];

static int get_scheduler_type_by_name(char *name) {
    if (strcmp(name, "wrr") == 0) {
        return SCHEDULER_TYPE_WRR;
    }
    return SCHEDULER_TYPE_MAX;
}

struct scheduler* get_scheduler(char *name) {
    int sch_type = get_scheduler_type_by_name(name);
    if (sch_type >= SCHEDULER_TYPE_MAX) {
        return NULL;
    }
    return &scheduler_array[sch_type];
}