//
// Created by tedqu on 25-4-11.
//

#include <rte_common.h>
#include <stdlib.h>
#include <string.h>
#include <toml.h>
#include <errno.h>
#include "list.h"
#include "conf.h"

#define CONF_FILE_PATH "../conf.toml"

static struct list_head conf_items;

static void parse_item_array(toml_array_t *array, struct conf_item *parser) {
    int n = toml_array_nelem(array);
    for (int i = 0; i < n; i++) {
        toml_table_t * item = toml_table_at(array, i);
        parser->parse_func(parser, item);
    }
}

void add_conf_item_parser(struct conf_item *item) {
    struct conf_item *curr;

    list_for_each_entry(curr, &conf_items, item_node) {
        if (strcmp(item->name, curr->name) == 0) {
            rte_exit(EXIT_FAILURE, "conf item parser %s already in\n", item->name);
        }
    }
    list_add(&item->item_node, &conf_items);
}

void parse_conf(char *conf_path) {
    FILE* fp;
    char err_buf[256];

    fp = fopen(CONF_FILE_PATH, "r");
    if (!fp) {
        rte_exit(EXIT_FAILURE, "%s: cannot open %s, %s", __func__, CONF_FILE_PATH, strerror(errno));
    }

    bzero(err_buf, sizeof(err_buf));
    toml_table_t* conf = toml_parse_file(fp, err_buf, sizeof(err_buf));
    fclose(fp);

    struct conf_item *curr;
    list_for_each_entry(curr, &conf_items, item_node) {
        toml_array_t *array = toml_array_in(conf, curr->name);
        if (NULL == array) {
            rte_exit(EXIT_FAILURE, "%s: no % conf", __func__, curr->name);
        }
        parse_item_array(array, curr);
    }
    toml_free(conf);
}

void parse_module_init(void) {
    INIT_LIST_HEAD(&conf_items);
}