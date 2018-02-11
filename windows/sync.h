#ifndef PUTTY_SYNC_H
#define PUTTY_SYNC_H

#include <wininet.h>

typedef struct {
    char url[1024];
    char username[64];
    char password[64];
} sync_settings;

void win_setup_config_box_sync_buttons(struct controlbox *b, HWND *hwndp,
                                       int has_help, int midsession);

#endif
