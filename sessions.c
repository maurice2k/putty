#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "sessions.h"

// session name cleanup
static char* session_name_cleanup(char* name)
{
    int i, skip = 0, ws=0, lastdc=-1;
    for (i = 0; i < strlen(name); ++i) {
        if (name[i] == ' ') {
            ws++;
        } else if (name[i] == SESSION_SEPARATOR) {
            if (ws == i - (lastdc + 1)) {
                // we have yet another double colon with nothing or space in between, skip it
                skip++;
            }
            lastdc = i;
            skip += ws;
            ws = 0;
        } else if (ws == i - (lastdc + 1)) {
            skip += ws;
            ws = 0;
        } else {
            ws = 0;
        }
        if (skip > 0) {
            name[i - skip] = name[i];
        }
    }

    name[i - skip - ws] = '\0';

    if (lastdc + ws == i - 1) {
        // only whitespace and double colons at the end
        name[lastdc - skip] = 0;
    }
    return name;
}

// compare session names
static int session_cmp(const char *a, const char *b)
{
    /*
     * Alphabetical order, except that "Default Settings" is a
     * special case and comes first.
     */
    if (!strcmp(a, DEFAULT_SETTINGS_SESSION)) {
        return -1;
    }

    if (!strcmp(b, DEFAULT_SETTINGS_SESSION)) {
        return +1;
    }

    return strcmp(a, b);
}

// create tree structure
session_tree *session_tree_create()
{
    session_tree *sess_tree = malloc(sizeof(session_tree));
    sess_tree->nodes = 0;
    sess_tree->root_node = session_node_create("ROOT NODE", -1);
    sess_tree->node_user_data_free_callback = NULL;
    
    return sess_tree;
}

// free the tree structure
void session_tree_free(session_tree *sess_tree)
{
    assert(sess_tree != NULL);
    if (sess_tree->root_node != NULL) {
        session_node_free(sess_tree, sess_tree->root_node);
    }
    free(sess_tree);
}

// insert child node for parent node before given reference node
session_node *session_node_insert_child_before(session_node *parent, session_node *reference_sibling, char *name, int index)
{
    session_node *sess_node, *child;

    if (parent->first_child == NULL && reference_sibling != NULL) {
        return NULL;
    }

    sess_node = session_node_create(name, index);
    sess_node->parent = parent;

   /* if (parent->first_child == NULL) {
        parent->first_child = sess_node;
        return sess_node;
    }*/

    child = parent->first_child;

    if (child == reference_sibling) {
        // insert before first element
        sess_node->next_sibling = reference_sibling;
        parent->first_child = sess_node;

    } else {
        // insert before reference sibling (or at the end if reference_sibling is NULL)
        while (child->next_sibling != reference_sibling && child->next_sibling != NULL) {
            child = child->next_sibling;
        }

        sess_node->next_sibling = reference_sibling;
        child->next_sibling = sess_node;

    }

    return sess_node;
}

// inserts node based on name in sorted order. if a node with the same name already exists
// no new node is inserted and the existing node is being returned. otherwise the new node is returned.
session_node *session_node_insert_sorted_unique_name(session_node *parent, char *name, int index)
{
    session_node *sess_node, *child, *prev_child;

    if (parent->first_child == NULL) {
        parent->first_child = session_node_create(name, index);
        parent->first_child->parent = parent;
        return parent->first_child;
    }

    child = parent->first_child;
    prev_child = child;

    while (child != NULL) {
        int cmp = session_cmp(child->name, name);
        if (cmp == 0) {
            return child; // child with given name already exists
        } else if (cmp > 0) {
            sess_node = session_node_create(name, index);
            sess_node->next_sibling = child;

            if (child == prev_child) {
                // insert before first child
                parent->first_child = sess_node;
                sess_node->parent = parent;
            } else {
                prev_child->next_sibling = sess_node;
                sess_node->parent = parent;
            }

            return sess_node;
        }

        prev_child = child;
        child = child->next_sibling;
    }

    prev_child->next_sibling = session_node_create(name, index);
    prev_child->next_sibling->parent = parent;
    return prev_child->next_sibling;
}

// get last sibling for given node
session_node *session_node_get_last_sibling(session_node *sess_node)
{
    if (sess_node != NULL) {
        while (sess_node->next_sibling != NULL) {
            sess_node = sess_node->next_sibling;
        }
    }
    return sess_node;
}

// create a new node
session_node *session_node_create(char *name, int index)
{
    session_node *sess_node = malloc(sizeof(session_node));
    sess_node->name = malloc(strlen(name) + 1);
    strcpy(sess_node->name, name);
    sess_node->index = index;
    sess_node->user_data = NULL;
    sess_node->first_child = NULL;
    sess_node->next_sibling = NULL;
    sess_node->parent = NULL;
    return sess_node;
}

// free the given node and all child nodes/siblings
void session_node_free(session_tree *sess_tree, session_node *sess_node)
{
    if (sess_node == NULL) {
        return;
    }
    if (sess_node->first_child != NULL) {
        session_node_free(sess_tree, sess_node->first_child);
        sess_node->first_child = NULL;
    }

    if (sess_node->next_sibling != NULL) {
        session_node_free(sess_tree, sess_node->next_sibling);
        sess_node->next_sibling = NULL;
    }
    
    if (sess_node->user_data != NULL &&
        sess_tree->node_user_data_free_callback) {
            (*sess_tree->node_user_data_free_callback)(sess_node->user_data, sess_node);
    }

    free(sess_node->name);
    free(sess_node);
    sess_node = NULL;
}

// adds one or more nodes given a flattened name using : as separator
void session_tree_add_flat_name(session_tree *sess_tree, const char *flat_name, int index)
{
    session_node *sess_node;
    char *name, *p, *dc;

    name = malloc(strlen(flat_name) + 1);
    strcpy(name, flat_name);
    session_name_cleanup(name);

    dc = name;
    p = name;
    sess_node = sess_tree->root_node;

    while ((dc = strchr(dc, SESSION_SEPARATOR))) {
        int len = dc - p;

        p[len] = 0;
        sess_node = session_node_insert_sorted_unique_name(sess_node, p, -1);

        dc++;
        p = dc;
    }

    sess_node = session_node_insert_sorted_unique_name(sess_node, p, index);

    free(name);
}

// traverse session node tree and call <traverse_callback> for each item
// <extra_data> is passed thru to the callback
void *session_node_traverse(session_node *root_node,
    session_node_traverse_callback traverse_callback, void *extra_data) {
    session_node *current;
    static int level = 0;
    void *res;

    current = root_node->first_child;
    while (current != NULL) {
        if ((res = (*traverse_callback)(current, root_node, current->first_child == NULL,
            level, extra_data)) != NULL) {
            return res;
        }
        level++;
        if ((res = session_node_traverse(current, traverse_callback, extra_data)) != NULL) {
            return res;
        }
        level--;
        current = current->next_sibling;
    }
    return NULL;
}

// reload session tree from given sesslist struct
void session_tree_reload_from_sesslist(session_tree **sess_tree, struct sesslist *sesslist)
{
    int i;
    if (*sess_tree == NULL) {
        *sess_tree = session_tree_create();
    } else {
        session_node_free(*sess_tree, (*sess_tree)->root_node->first_child);
        (*sess_tree)->root_node->first_child = NULL;
    }

    for (i = 0; i < sesslist->nsessions; ++i) {
        session_tree_add_flat_name(*sess_tree, sesslist->sessions[i], i);
    }
}

// sets callback function that is used to free user_data in session nodes
void session_tree_set_node_user_data_free_callback(session_tree *sess_tree,
    session_node_user_data_free_callback free_callback) 
{
    sess_tree->node_user_data_free_callback = free_callback;
}

static void *_session_node_find_cb(session_node *current, session_node *parent, int is_leaf, int level, void *extra_data)
{
    if (is_leaf && current->index == *((int *)extra_data)) {
        return current;
    }
    return NULL;
}

// searches for leaf session nodes with given index
session_node *session_tree_find_leaf_node_by_index(session_tree *sess_tree, int index)
{
    return session_node_traverse(sess_tree->root_node, _session_node_find_cb, &index);
}
