//
// Created by tedqu on 25-4-11.
//

#ifndef NAT_LB_CONF_H
#define NAT_LB_CONF_H

#include <toml.h>
#include "list.h"

#define CONF_ITEM_MAX_FIELD 64
#define CONF_ITEM_NAME_LENGTH 64

struct conf_item;
typedef void(*conf_item_parse_func)(struct conf_item *item, toml_table_t *array);

struct conf_item {
    struct list_head item_node;
    char name[CONF_ITEM_NAME_LENGTH];
    conf_item_parse_func parse_func;
};

void add_conf_item_parser(struct conf_item *item);
void parse_conf(char *conf_path);
void parse_module_init(void);

#endif //NAT_LB_CONF_H
