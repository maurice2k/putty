#define _WIN32_WINNT 0x600

#include <assert.h>
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <wininet.h>

#include "putty.h"
#include "winstuff.h"
#include "win_res.h"
#include "dialog.h"
#include "storage.h"
#include <commctrl.h>

#include "sync.h"

static char *format_windows_error(DWORD last_error);

#define RETURN_ERROR(message) ret = message; goto done;
#define RETURN_WINDOWS_ERROR() ret = format_windows_error(GetLastError());\
    goto done;

#define MAX_DOWNLOAD_LENGTH 5 * 1024 * 1024

sync_settings *settings = NULL;

static sync_settings *load_sync_settings()
{
    sync_settings *settings = snew(sync_settings);
    HKEY rkey;
    char *str;

    memset(settings, 0, sizeof(*settings));

    if (RegOpenKey(HKEY_CURRENT_USER, PUTTY_REG_POS, &rkey) == ERROR_SUCCESS) {
        
        if ((str = read_setting_s(rkey, "SyncUrl")) != NULL) {
            strncpy(settings->url, str, sizeof(settings->url) - 1);
            sfree(str);
        }

        if ((str = read_setting_s(rkey, "SyncUsername")) != NULL) {
            strncpy(settings->username, str, sizeof(settings->username) - 1);
            sfree(str);
        }

        if ((str = read_setting_s(rkey, "SyncPassword")) != NULL) {
            strncpy(settings->password, str, sizeof(settings->password) - 1);
            sfree(str);
        }

        RegCloseKey(rkey);
    }

    return settings;
}

static void save_sync_settings(sync_settings *settings)
{
    HKEY rkey;

    if (RegOpenKey(HKEY_CURRENT_USER, PUTTY_REG_POS, &rkey) == ERROR_SUCCESS) {
        
        write_setting_s(rkey, "SyncUrl", (const char *)&settings->url);
        write_setting_s(rkey, "SyncUsername", (const char *)&settings->username);
        write_setting_s(rkey, "SyncPassword", (const char *)&settings->password);

        RegCloseKey(rkey);
    }
}

static void free_sync_settings(sync_settings *settings)
{
    sfree(settings);
}

static char *clone_default_session(const char *target_name)
{
    char *err_msg = NULL, *name = NULL, *ret = NULL;
    LPBYTE value = NULL;
    DWORD i = 0;
    DWORD nameSize = 32767;
    DWORD valueSize;
    DWORD type = 0;
    DWORD synced_session
     = 1;
    LONG res;
    HKEY default_sess_key = NULL;
    HKEY target_sess_key = NULL;

    default_sess_key = open_settings_r(NULL);
    if (default_sess_key == NULL) {
        RETURN_ERROR(dupprintf("Unable to load default settings to clone "\
            "from for %s", target_name));
    }

    del_settings(target_name); // remove the target session if already existant

    target_sess_key = open_settings_w(target_name, &err_msg);
    if (target_sess_key == NULL) {
        RETURN_ERROR(dupprintf("Unable to create settings for %s: %s",
            target_name, err_msg));
    }
        
    name = snewn(32768, char);
    value = snewn(65536, BYTE);

    for (i = 0; ; i++) {
        nameSize = 32767;  // max size for names
        valueSize = 65535;

        res = RegEnumValue(default_sess_key, i, name, &nameSize, NULL, &type,
            value, &valueSize);
        if (res == ERROR_MORE_DATA) {
            // value is larger than 64kB, we're skipping this as PuTTY's config
            // has no such long (string) values
            continue;
        }
        if (res != ERROR_SUCCESS || res == ERROR_NO_MORE_ITEMS) {
            break;
        }

        res = RegSetValueEx(target_sess_key, name, 0, type, value, valueSize);
        if (res != ERROR_SUCCESS) {
            RETURN_WINDOWS_ERROR();
        }
    }

    RegSetValueEx(target_sess_key, "SyncedSession", 0, REG_DWORD,
        &synced_session, sizeof(synced_session));

done:
    if (err_msg != NULL) {
        sfree(err_msg);
    }

    if (err_msg != NULL) {
        sfree(err_msg);
    }

    if (default_sess_key) {
        close_settings_r(default_sess_key);
    }

    if (target_sess_key) {
        close_settings_w(target_sess_key);
    }

    return ret;
}

static char *parse_json_response(const char *json_buf)
{
    return clone_default_session("nasty nice");
    return NULL;
}

char *sync_sessions()
{
    char *ret = NULL;
    char host[512], path[512];
    unsigned int port;
    sync_settings *s = load_sync_settings();
    LPURL_COMPONENTS uc = snew(URL_COMPONENTS);
    static const char *acceptTypes[] = {"application/json", "text/*", NULL};
    DWORD flags = 0;
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hFile = NULL;
    int res;
    DWORD bytes_read = 0;
    char *buf = NULL;
    int buf_len = 0;
    int buf_cap = 0;

    if (strlen(s->url) == 0) {
        RETURN_ERROR(dupprintf("No sync endpoint URL configured in sync "\
            "settings!"));
    }

    memset(&host, 0, sizeof(host));
    memset(&path, 0, sizeof(path));

    memset(uc, 0, sizeof(URL_COMPONENTS));
    uc->dwStructSize = sizeof(URL_COMPONENTS);
    uc->dwSchemeLength = 1;
    uc->dwHostNameLength = 1;
    uc->dwUrlPathLength = 1;

    if (InternetCrackUrl((LPCSTR)&s->url, strlen((char *)&s->url), 0, uc)
        == FALSE) {
        RETURN_WINDOWS_ERROR();
    }

    if (uc->dwHostNameLength > sizeof(host) - 1 ||
        uc->dwUrlPathLength > sizeof(path) - 1) {
        RETURN_WINDOWS_ERROR();
    }

    strncpy(host, uc->lpszHostName, min(uc->dwHostNameLength, sizeof(host) - 1));
    strncpy(path, uc->lpszUrlPath, min(uc->dwUrlPathLength, sizeof(path) - 1));
    port = uc->nPort;

    if (uc->nScheme == INTERNET_SCHEME_HTTPS) {
        flags |= INTERNET_FLAG_SECURE;
    }

    printf("Host: %s, Port: %d; Path: %s\n", host, uc->nPort, path);

    // open wininet handle
    hSession = InternetOpen("PuTTY Sync", INTERNET_OPEN_TYPE_PRECONFIG,
                            NULL, NULL, 0);
    if (hSession == NULL) {
        RETURN_WINDOWS_ERROR();
    }

    // connect (does nothing in case of HTTP)
    hConnect = InternetConnect(hSession, host, port,
                            s->username, s->password,
                            INTERNET_SERVICE_HTTP, 0, 0);
    if (hConnect == NULL) {
        RETURN_WINDOWS_ERROR();
    }

    // create request handle
    flags |= INTERNET_FLAG_RELOAD;
    hFile = HttpOpenRequest(hConnect, "GET", path, NULL, NULL,
                            acceptTypes, flags, 0);
    if (hFile == NULL) {
        RETURN_WINDOWS_ERROR();
    }

    // send the request without body
    if (!HttpSendRequest(hFile, NULL, 0, NULL, 0)) {
        RETURN_WINDOWS_ERROR();
    }

    {
        DWORD statusCode = 0;
        DWORD length = sizeof(DWORD);
        HttpQueryInfo(hFile, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
            &statusCode, &length, NULL);

        if (statusCode == 403) {
            RETURN_ERROR(dupprintf("Sync endpoint credentials seem to be "\
                "incorrect (HTTP status code 403)."))
        }
        
        if (statusCode < 200 || statusCode >= 300) {
            RETURN_ERROR(dupprintf("Sync endpoint returned with HTTP status "\
                "code %ld.", statusCode))
        }

    }

    // retrieve response
    buf_cap = 8192;
    buf_len = 0;
    buf = snewn(buf_cap, char);
    do {
        if (buf_len + 1024 >= buf_cap) {
            buf_cap += 8192;
            buf = sresize(buf, buf_cap, char);
        }
        res = InternetReadFile(hFile, buf + buf_len, 1024, &bytes_read);
        buf_len += bytes_read;
    } while (res && bytes_read > 0 && buf_len < MAX_DOWNLOAD_LENGTH);

    buf[buf_len] = 0;

    if (buf_len >= MAX_DOWNLOAD_LENGTH) {
        RETURN_ERROR(dupprintf("Download length of %i kB exceeded!",
            MAX_DOWNLOAD_LENGTH / 1024));
    }

    // parse json
    ret = parse_json_response(buf);
    if (ret != NULL) {
        goto done;
    }

    printf("BUFFER: %s\n", buf);
    
done:
    if (s) {
        free_sync_settings(s);
    }
    if (uc) {
        sfree(uc);
    }
    if (buf) {
        sfree(buf);
    }
    if (hFile) {
        InternetCloseHandle(hFile);
    }
    if (hConnect) {
        InternetCloseHandle(hConnect);
    }
    if (hSession) {
        InternetCloseHandle(hSession);
    }
    
    return ret;
}

static char *format_windows_error(DWORD last_error)
{
    char *res;
    LPTSTR lpMsgBuf = NULL;
    DWORD dwBaseLength = FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_HMODULE |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        GetModuleHandle(TEXT("wininet.dll")),
        last_error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0,
        NULL
    );
    
    if (dwBaseLength > 0) {
        res = dupprintf("Error #%ld: %s", last_error, lpMsgBuf);
        LocalFree(lpMsgBuf);
        return res;
    } else {
        return dupprintf("Error #%ld: %s", last_error,
        "(no error message as FormatMessage failed)");
    }
}

static DWORD WINAPI sync_sessions_thread_proc(void *param)
{
    char* error_msg;

    error_msg = sync_sessions(&error_msg);

    if (error_msg != NULL) {
        MessageBox((HWND)param, error_msg, "Syncing error", MB_OK);
        sfree(error_msg);
    }

    EnableWindow((HWND)param, 1);
    return 0;
}

static INT_PTR CALLBACK SyncSettingsProc(HWND hwnd, UINT msg,
                                  WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
      case WM_INITDIALOG:
        {
            SetDlgItemText(hwnd, IDC_SYNC_URL, settings->url);
            SetDlgItemText(hwnd, IDC_SYNC_USERNAME, settings->username);
            SetDlgItemText(hwnd, IDC_SYNC_PASSWORD, settings->password);

            if (strcmp(settings->url, "") == 0) {
                SetFocus(GetDlgItem(hwnd, IDC_SYNC_URL));
                return 0;
            }
        }
        return 1;
      case WM_NOTIFY:
        {
            LPNMHDR nmh = (LPNMHDR)lParam;
            PNMLINK pNMLink = (PNMLINK)lParam;
            LITEM   item    = pNMLink->item;
            if (nmh->code == NM_CLICK && nmh->idFrom == IDC_SYNC_INFO) {
                ShellExecuteW(hwnd, L"open", item.szUrl,
                              NULL, NULL, SW_SHOWDEFAULT);
            }
            return 0;
        }
      case WM_COMMAND:
        switch (LOWORD(wParam)) {
          case IDOK:
            GetDlgItemText(hwnd, IDC_SYNC_URL, (LPSTR)&settings->url,
                sizeof(settings->url));
            GetDlgItemText(hwnd, IDC_SYNC_USERNAME, (LPSTR)&settings->username,
                sizeof(settings->username));
            GetDlgItemText(hwnd, IDC_SYNC_PASSWORD, (LPSTR)&settings->password,
                sizeof(settings->password));
            save_sync_settings(settings);
          case IDCANCEL:
            free_sync_settings(settings);
            EndDialog(hwnd, TRUE);
            return 0;
        }
        return 0;
      case WM_CLOSE:
        free_sync_settings(settings);
        EndDialog(hwnd, TRUE);
        return 0;
    }

    return 0;
}
//http://archive.ubuntu.com/ubuntu/dists/artful/main/installer-amd64/current/images/netboot/mini.isox

HWND get_hwnd_by_ctrl(union control *ctrl, void *dlg)
{
    struct dlgparam *dp = (struct dlgparam *)dlg;
    struct winctrl *c = NULL;
    int i = 0;

    for (i = 0; i < dp->nctrltrees; i++) {
        c = winctrl_findbyctrl(dp->controltrees[i], ctrl);
        if (c) {
            break;
        }
    }
    if (c == NULL) {
        return NULL;
    }

    return GetDlgItem(dp->hwnd, c->base_id);
}

static void modal_sync_settings(HWND hwnd)
{
    EnableWindow(hwnd, 0);
    DialogBox(hinst, MAKEINTRESOURCE(IDD_SYNC_SETTINGS), hwnd,
              SyncSettingsProc);
    EnableWindow(hwnd, 1);
    SetActiveWindow(hwnd);
}

void sync_down_handler(union control *ctrl, void *dlg,
			  void *data, int event)
{
    HANDLE th;
    DWORD threadid;
    HWND button = get_hwnd_by_ctrl(ctrl, dlg);
    if (event == EVENT_ACTION) {
        th = CreateThread(NULL, 0, sync_sessions_thread_proc,
                          button, 0, &threadid);
        if (th) {
            EnableWindow(button, 0);
            CloseHandle(th); // we don't need the handle
        }
    }
}

void sync_settings_handler(union control *ctrl, void *dlg,
			  void *data, int event)
{
    HWND *hwndp = (HWND *)ctrl->generic.context.p;

    if (event == EVENT_ACTION) {
        settings = load_sync_settings();
	modal_sync_settings(*hwndp);
    }
}

void win_setup_config_box_sync_buttons(struct controlbox *b, HWND *hwndp,
                                       int has_help, int midsession)
{
    struct controlset *s;
    union control *c;

    s = ctrl_getset(b, "Session", "savedsessions", "");
    ctrl_columns(s, 3, 37, 38, 25);
    c = ctrl_pushbutton(s, "Sync down", '1', HELPCTX(no_help),
        sync_down_handler, P(hwndp));
    c->generic.column = 0;
    c = ctrl_pushbutton(s, "Sync settings", '2', HELPCTX(no_help),
        sync_settings_handler, P(hwndp));
    c->generic.column = 1;
}
