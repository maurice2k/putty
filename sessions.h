#ifndef PUTTY_SESSIONS_H
#define PUTTY_SESSIONS_H

#include "putty.h"

#define DEFAULT_SETTINGS_SESSION "Default Settings"
#define SESSION_SEPARATOR ':'

typedef struct session_node {
    char *name;
    int index;
    void *data;
    struct session_node *parent;
    struct session_node *first_child;
    struct session_node *next_sibling;
} session_node;

typedef struct session_tree {
    int nodes;
    session_node *root_node;
} session_tree;

typedef void *(*session_node_traverse_callback)(session_node *current,
    session_node *parent, int is_leaf, int level, void *extra_data);

session_tree *session_tree_create();
void session_tree_add_flat_name(session_tree *sess_tree, const char *flat_name,
    int index);

void session_tree_free(session_tree *sess_tree);

session_node *session_node_insert_child_before(session_node *parent,
    session_node *reference_sibling, char *name, int index);
session_node *session_node_insert_sorted_unique_name(session_node *parent, char *name,
    int index);

session_node *session_node_create(char *name, int index);
void session_node_free(session_node *sess_node);

void *session_node_traverse(session_node *root_node,
    session_node_traverse_callback traverse_callback, void *extra_data);

void session_tree_reload_from_sesslist(session_tree **sess_tree, struct sesslist *sesslist);

session_node *session_tree_find_leaf_node_by_index(session_tree *sess_tree, int index);

#endif
