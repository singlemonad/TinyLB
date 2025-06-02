//
// Created by tedqu on 24-9-5.
//

#ifndef NAT_LB_LIST_H
#define NAT_LB_LIST_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

struct list_head {
    struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) {&{name}, &{name}}

#undef LIST_HEAD
#define LIST_HEAD(name) \
    struct list_head name = LIST_HEAD_INIT(name)

static void INIT_LIST_HEAD(struct list_head* list) {
    list->prev = list;
    list->next = list;
}

static void list_add_rcu(struct list_head *node, struct list_head *prev, struct list_head *next) {
    node->prev = prev;
    node->next = next;
    prev->next = node;
    next->prev = node;
}

static void list_add(struct list_head *node, struct list_head* head) {
    list_add_rcu(node, head, head->next);
}

static void list_del_rcu(struct list_head *prev, struct list_head *next) {
    prev->next = next;
    next->prev = prev;
}

static void list_del_entry(struct list_head *entry) {
    list_del_rcu(entry->prev, entry->next);
}

static void list_del(struct list_head *entry) {
    list_del_entry(entry);
    entry->prev = NULL;
    entry->next = NULL;
}

static int list_elems(struct list_head *head) {
    int n = 0;

    struct list_head *curr = head->next;
    while (curr != head) {
        n++;
        curr = curr->next;
    }
    return n;
}

#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
    list_entry((ptr)->next, type, member)

#define list_tail_entry(ptr, type, member) \
    list_entry((ptr)->prev, type, member)

#define list_next_entry(pos, member) \
    list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_prev_entry(pos, member) \
    list_entry((pos)->prev, typeof(*(pos)), member)

#define list_for_each_entry(pos, head, member) \
    for(pos = list_first_entry(head, typeof(*pos), member); \
        &pos->member != head;   \
        pos = list_next_entry(pos, member))

#define list_for_each_entry_continue(pos, head, member) \
    for(pos = list_entry(pos->member.next, typeof(*pos), member); \
        &pos->member != head;   \
        pos = list_next_entry(pos, member))


#endif //NAT_LB_LIST_H
