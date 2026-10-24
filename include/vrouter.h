#ifndef VROUTER_H
#define VROUTER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VROUTER_ABI_VERSION 2u

/*
 * The native library uses the host's POSIX threads. Android bionic provides
 * them; Linux consumers of an older libc should link with -pthread.
 */

typedef void *vrouter_t;

enum {
    VROUTER_OK = 0,
    VROUTER_ERR_INVALID_ARGUMENT = -1,
    VROUTER_ERR_INVALID_CONFIG = -2,
    VROUTER_ERR_OUT_OF_MEMORY = -3,
    VROUTER_ERR_BUSY = -4,
    VROUTER_ERR_UNSUPPORTED = -5,
    VROUTER_ERR_PERMISSION = -6,
    VROUTER_ERR_IO = -7,
    VROUTER_ERR_NOT_FOUND = -8,
    VROUTER_ERR_INTERNAL = -9
};

enum {
    VROUTER_EVENT_STARTED = 1,
    VROUTER_EVENT_STOPPED = 2,
    VROUTER_EVENT_ERROR = 3
};

typedef struct vrouter_status {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t running;
    uint32_t port_count;
    uint64_t uptime_ms;
} vrouter_status_t;

typedef void (*vrouter_event_cb)(void *user, int event, const char *message);

/*
 * Create an instance from a complete JSON config. Returns NULL when the JSON
 * is malformed or fails validation. The input buffer is not retained.
 *
 * Hosts may configure an existing L3 port (kind "l3" without "create") and
 * inject its descriptor with vrouter_set_port_fd before vrouter_start.
 */
vrouter_t vrouter_create(const char *config_json);

/* Starts the data plane. Blocks until startup succeeds or fails. */
int vrouter_start(vrouter_t handle);

/* Stops the data plane and joins the data-plane thread. Idempotent. */
int vrouter_stop(vrouter_t handle);

/* Stops if needed and releases all native resources. */
void vrouter_destroy(vrouter_t handle);

/*
 * Bind a host-owned descriptor to a configured L3 port.
 *
 * The descriptor is borrowed: vRouter duplicates it during vrouter_start, so
 * the caller keeps ownership and may close it after vrouter_start returns.
 * It must remain valid for every vrouter_start call. A stopped handle reuses
 * the same bindings when restarted. Call before vrouter_start.
 *
 * vRouter sets O_NONBLOCK on the duplicate. Since dup() shares the open file
 * description, the original descriptor also becomes non-blocking.
 */
int vrouter_set_port_fd(vrouter_t handle, const char *name, int fd);

/*
 * Install a lifecycle callback. Events run on the data-plane thread. STARTED
 * is delivered before vrouter_start returns. Do not call vrouter_* functions
 * other than vrouter_get_status from inside the callback; vrouter_stop and
 * vrouter_destroy would deadlock. Keep callbacks short. `message` may be NULL
 * and is valid only for the duration of the callback.
 */
int vrouter_set_event_cb(vrouter_t handle, vrouter_event_cb callback,
                         void *user);

/* Fill a caller-owned status snapshot. */
int vrouter_get_status(vrouter_t handle, vrouter_status_t *status);

/* Returns a static NUL-terminated version string. */
const char *vrouter_version(void);

#ifdef __cplusplus
}
#endif

#endif
