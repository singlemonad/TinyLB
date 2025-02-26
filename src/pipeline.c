//
// Created by tedqu on 24-11-18.
//

#include "../include/pipeline.h"
#include "../include/common.h"
#include "../include/log.h"

#define MAX_PIPELINE_FUNC	16

typedef struct pipeline_entry {
    char name[32];
    pipeline_func func;
    void *data;
    int priority;
}pipeline_entry_t;

pipeline_entry_t g_pipeline_entry_array[MAX_PIPELINE_FUNC];

int pipeline_register(const char *name, pipeline_func func, int priority, void *data) {
    int i, j;

    if (g_pipeline_entry_array[MAX_PIPELINE_FUNC - 1].func != NULL) {
        RTE_LOG(ERR, EAL, "pipeline funcs already full\n");
        return NAT_LB_EXIST;
    }

    if (strlen(name) >= sizeof(g_pipeline_entry_array[0].name)) {
        RTE_LOG(ERR, EAL, "pipeline func name %s too long\n", name);
        return -1;
    }

    for (i = 0; i < MAX_PIPELINE_FUNC; i++) {
        if (g_pipeline_entry_array[i].func == NULL ||
            g_pipeline_entry_array[i].priority > priority)
            break;
    }

    for (j = MAX_PIPELINE_FUNC - 1; j > i; j--) {
        memcpy(&g_pipeline_entry_array[j], &g_pipeline_entry_array[j - 1], sizeof(pipeline_entry_t));
    }

    strcpy(g_pipeline_entry_array[i].name, name);
    g_pipeline_entry_array[i].func = func;
    g_pipeline_entry_array[i].data = data;
    g_pipeline_entry_array[i].priority = priority;

    RTE_LOG(INFO, EAL, "register pipeline func %s, priority %d successful\n", name, priority);

    return 0;
}

pipeline_actions run_pipeline_for_skb(struct sk_buff *skb) {
    int action;

    int i;
    for (i = 0; g_pipeline_entry_array[i].func != NULL; i++) {
        action = g_pipeline_entry_array[i].func(skb);
        switch (action) {
            case PIPELINE_ACTION_NEXT:
                continue;
            case PIPELINE_ACTION_OUTPUT:
            case PIPELINE_ACTION_DROP:
            case PIPELINE_ACTION_STOLEN:
                break;
            default:
                /* should never be here */
                RTE_LOG(ERR, EAL, "unknown action(%d) returned by pipeline function"
                          "(priority %d), dropped\n", action, g_pipeline_entry_array[i].priority);
        }
        break;
    }

    return action;
}