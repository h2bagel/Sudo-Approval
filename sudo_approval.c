/*
 sudo-approval plugin (fork)

 Original code (MIT License)
 Copyright (c) 2024 e792a8

 Modifications (LGPL v3)
 Copyright (c) 2026 h2bagel

 This file combines MIT-licensed code with LGPL-licensed modifications.

 See LICENSE file in the project root for full license texts.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <pwd.h>
#include <grp.h>
#include <locale.h>
#include <libintl.h>
#include <signal.h>
#include <wchar.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sudo_plugin.h>

#define _(STRING) gettext(STRING)
#define LOG_MSG_TYPE (SUDO_CONV_INFO_MSG | SUDO_CONV_PREFER_TTY)
#define CMD_LINE_MAX 4096
#define PROMPT_TIMEOUT 30

#define COLOR_RED "\x1b[31m"
#define COLOR_RESET "\x1b[0m"

struct approval_context {
    sudo_conv_t sudo_conv;
    sudo_printf_t sudo_log;
    int option_yes;
    int option_noconfirm;
    uid_t runas_uid;
    gid_t runas_gid;
    const char *runas_user;
    const char *runas_group;
    struct termios orig_termios;
    int tty_fd;
};

static struct approval_context ctx;

/* ---------- Terminal safety ---------- */
static void restore_terminal(int signo) {
    if (ctx.tty_fd >= 0)
        tcsetattr(ctx.tty_fd, TCSANOW, &ctx.orig_termios);
    _exit(128 + signo);
}

static int enforce_terminal_available(void) {
    ctx.tty_fd = open("/dev/tty", O_RDONLY);
    if (ctx.tty_fd < 0) {
        ctx.sudo_log(SUDO_CONV_ERROR_MSG, _("No controlling terminal.\n"));
        return 0;
    }
    if (!isatty(ctx.tty_fd)) {
        ctx.sudo_log(SUDO_CONV_ERROR_MSG, _("Not a terminal.\n"));
        close(ctx.tty_fd);
        ctx.tty_fd = -1;
        return 0;
    }
    return 1;
}

/* ---------- Secure logging ---------- */
static void log_suspicious(const char *msg, const char *data) {
    int fd = open("/var/log/sudo_approval.log",
                  O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
    if (fd < 0) return;

    FILE *f = fdopen(fd, "a");
    if (!f) {
        close(fd);
        return;
    }

    char safe_msg[512], safe_data[512];
    snprintf(safe_msg, sizeof(safe_msg), "%s", msg ? msg : "(null)");
    snprintf(safe_data, sizeof(safe_data), "%s", data ? data : "(null)");

    fprintf(f, "[sudo_approval warning] %s: %s\n", safe_msg, safe_data);
    fclose(f);
}

/* ---------- ANSI Escape Neutralization ---------- */
static void escape_ansi(const char *src, char *dest, size_t size) {
    size_t off = 0;
    for (; *src && off + 1 < size; src++) {
        if (*src == 0x1b) {  // ESC sequence start
            src++;
            while (*src && *src != 'm') src++;
            if (*src) continue;
        }
        dest[off++] = *src;
    }
    dest[off] = '\0';
}

/* ---------- Sensitive Command Redaction ---------- */
static void redact_sensitive(char *dest, const char *src, size_t size) {
    size_t off = 0;
    while (*src && off + 1 < size) {
        if ((strncmp(src, "pass=", 5) == 0) || (strncmp(src, "-p", 2) == 0)) {
            const char *eq = strchr(src, '=');
            off += snprintf(dest + off, size - off, "%.*s***",
                            (int)(eq ? (eq - src + 1) : 2), src);
            while (*src && *src != ' ') src++;
        } else {
            dest[off++] = *src++;
        }
    }
    dest[off] = '\0';
}

/* ---------- Command formatting ---------- */
static void build_command_line(char *dest, size_t size, char * const argv[]) {
    size_t off = 0;
    for (char * const *p = argv; *p; p++) {
        const char *arg = *p;
        int needs_quotes = strpbrk(arg, " \t\n\"\\$&|<>;`'") != NULL;
        int n;

        if (needs_quotes)
            n = snprintf(dest + off, size - off, "%s\"%s\"", off ? " " : "", arg);
        else
            n = snprintf(dest + off, size - off, "%s%s", off ? " " : "", arg);

        if (n < 0) break;

        if ((size_t)n >= size - off) {
            if (off + 4 < size) {
                strncpy(dest + size - 4, "...", 3);
                dest[size - 1] = '\0';
            }
            log_suspicious("Command truncated", arg);
            break;
        }
        off += (size_t)n;
    }
    if (off == 0) log_suspicious("Empty command detected", NULL);
    dest[size - 1] = '\0';
}

/* ---------- Environment Monitoring ---------- */
static void log_sensitive_env(char * const envp[]) {
    for (char * const *env = envp; env && *env; env++) {
        if (strncmp(*env, "LD_", 3) == 0 || strncmp(*env, "PATH=", 5) == 0) {
            log_suspicious("Sensitive environment variable detected", *env);
        }
    }
}

/* ---------- Input ---------- */
static wint_t get_single_char(int timeout_sec) {
    struct termios raw;
    tcgetattr(ctx.tty_fd, &ctx.orig_termios);
    raw = ctx.orig_termios;
    raw.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(ctx.tty_fd, TCSANOW, &raw);

    // Flush typeahead
    tcflush(ctx.tty_fd, TCIFLUSH);

    struct sigaction sa, oldint, oldterm, oldquit, oldhup;
    sa.sa_handler = restore_terminal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, &oldint);
    sigaction(SIGTERM, &sa, &oldterm);
    sigaction(SIGQUIT, &sa, &oldquit);
    sigaction(SIGHUP, &sa, &oldhup);

    fd_set fds;
    struct timeval tv = { timeout_sec, 0 };
    FD_ZERO(&fds);
    FD_SET(ctx.tty_fd, &fds);

    wint_t wc = 0;
    mbstate_t state;
    memset(&state, 0, sizeof(state));
    char buf[MB_CUR_MAX];

    if (select(ctx.tty_fd + 1, &fds, NULL, NULL, &tv) > 0) {
        size_t bytes_read = 0;
        while (bytes_read < MB_CUR_MAX) {
            ssize_t n = read(ctx.tty_fd, buf + bytes_read, 1);
            if (n <= 0) break;
            bytes_read += (size_t)n;
            size_t ret = mbrtowc(&wc, buf, bytes_read, &state);
            if (ret != (size_t)-2) break;
        }
    }

    tcsetattr(ctx.tty_fd, TCSANOW, &ctx.orig_termios);
    close(ctx.tty_fd);
    ctx.tty_fd = -1;

    sigaction(SIGINT, &oldint, NULL);
    sigaction(SIGTERM, &oldterm, NULL);
    sigaction(SIGQUIT, &oldquit, NULL);
    sigaction(SIGHUP, &oldhup, NULL);

    return wc;
}

/* ---------- Plugin API ---------- */
static int approval_open(unsigned int version, sudo_conv_t conversation,
                         sudo_printf_t printf_fn, char * const settings[],
                         char * const user_info[], int optind,
                         char * const argv[], char * const envp[],
                         char * const plugin_options[], const char **errstr)
{
    memset(&ctx, 0, sizeof(ctx));
    ctx.sudo_conv = conversation;
    ctx.sudo_log = printf_fn;

    setlocale(LC_ALL, "");
    bindtextdomain("sudo_approval", "/usr/share/locale");
    textdomain("sudo_approval");

    for (char * const *ui = settings; *ui; ui++) {
        if (strncmp(*ui, "runas_user=", 11) == 0)
            ctx.runas_user = *ui + 11;
        if (strncmp(*ui, "runas_group=", 12) == 0)
            ctx.runas_group = *ui + 12;
    }

    for (char * const *opt = plugin_options; opt && *opt; opt++) {
        if (strcmp(*opt, "yes") == 0) ctx.option_yes = 1;
        if (strcmp(*opt, "noconfirm") == 0) ctx.option_noconfirm = 1;
    }

    if (ctx.runas_user) {
        struct passwd *pw = getpwnam(ctx.runas_user);
        if (!pw) {
            ctx.sudo_log(SUDO_CONV_ERROR_MSG, _("Unknown user: %s\n"), ctx.runas_user);
            return 0;
        }
        ctx.runas_uid = pw->pw_uid;
        ctx.runas_gid = pw->pw_gid;
    }

    if (ctx.runas_group) {
        struct group *gr = getgrnam(ctx.runas_group);
        if (!gr) {
            ctx.sudo_log(SUDO_CONV_ERROR_MSG, _("Unknown group: %s\n"), ctx.runas_group);
            return 0;
        }
        ctx.runas_gid = gr->gr_gid;
    }

    return 1;
}

static int approval_check(char * const command_info[],
                          char * const run_argv[],
                          char * const run_envp[],
                          const char **errstr)
{
    if (!enforce_terminal_available())
        return 0;

    struct passwd *pw = getpwuid(ctx.runas_uid);
    const char *user_name = pw ? pw->pw_name : _("unknown");
    int is_root = (ctx.runas_uid == 0);

    char cmd[CMD_LINE_MAX];
    build_command_line(cmd, sizeof(cmd), run_argv);

    char safe_cmd[CMD_LINE_MAX];
    escape_ansi(cmd, safe_cmd, sizeof(safe_cmd));

    char redacted_cmd[CMD_LINE_MAX];
    redact_sensitive(redacted_cmd, safe_cmd, sizeof(redacted_cmd));

    log_sensitive_env(run_envp);

    const char *display_user = is_root ? _("Root") : user_name;
    char colored_user[256];
    escape_ansi(display_user, colored_user, sizeof(colored_user));

    if (is_root) {
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "%s%s%s", COLOR_RED, colored_user, COLOR_RESET);
        strncpy(colored_user, tmp, sizeof(colored_user));
        colored_user[sizeof(colored_user)-1] = '\0';
    }

    ctx.sudo_log(LOG_MSG_TYPE, _("Do you want to run '%s' as %s?\n"),
                 redacted_cmd, colored_user);
    ctx.sudo_log(LOG_MSG_TYPE, "%s", ctx.option_yes ? _("[Y/n] ") : _("[y/N] "));

    if (ctx.option_noconfirm)
        return 1;

    wint_t reply = get_single_char(PROMPT_TIMEOUT);
    ctx.sudo_log(LOG_MSG_TYPE, "%lc\n", reply ? reply : L'\n');

    if (!reply || reply == L'\n')
        return ctx.option_yes;

    if (reply == L'y' || reply == L'Y' ||
        reply == L'j' || reply == L'J')
        return 1;

    ctx.sudo_log(LOG_MSG_TYPE, _("Action cancelled.\n"));
    return 0;
}

static int approval_version(int verbose) {
    ctx.sudo_log(SUDO_CONV_INFO_MSG,
                 _("sudo approval plugin version %s\n"),
                 PACKAGE_VERSION);
    return 1;
}

struct approval_plugin sudo_approval = {
    .type = SUDO_APPROVAL_PLUGIN,
    .version = SUDO_API_VERSION,
    .open = approval_open,
    .check = approval_check,
    .show_version = approval_version
};
