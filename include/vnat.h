#ifndef VNAT_H
#define VNAT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VNAT_ABI_VERSION 1u

/*
 * The native library uses the host's POSIX threads. Android bionic provides
 * them; Linux consumers of an older libc should link with -pthread.
 */

typedef void *vnat_t;

enum {
    VNAT_OK = 0,
    VNAT_ERR_INVALID_ARGUMENT = -1,
    VNAT_ERR_INVALID_CONFIG = -2,
    VNAT_ERR_OUT_OF_MEMORY = -3,
    VNAT_ERR_BUSY = -4,
    VNAT_ERR_UNSUPPORTED = -5,
    VNAT_ERR_PERMISSION = -6,
    VNAT_ERR_IO = -7,
    VNAT_ERR_NOT_FOUND = -8,
    VNAT_ERR_INTERNAL = -9
};

enum {
    VNAT_EVENT_STARTED = 1,
    VNAT_EVENT_STOPPED = 2,
    VNAT_EVENT_ERROR = 3
};

typedef struct vnat_status {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t running;
    uint32_t port_count;
    uint64_t uptime_ms;
} vnat_status_t;

typedef void (*vnat_event_cb)(void *user, int event, const char *message);

/*
 * Create an instance from a complete JSON config. Returns NULL when the JSON
 * is malformed or fails validation. The input buffer is not retained.
 *
 * Hosts may configure an existing L3 port (kind "l3" without "create") and
 * inject its descriptor with vnat_set_port_fd before vnat_start.
 */
vnat_t vnat_create(const char *config_json);

/* Starts the data plane. Blocks until startup succeeds or fails. */
int vnat_start(vnat_t handle);

/* Stops the data plane and joins the data-plane thread. Idempotent. */
int vnat_stop(vnat_t handle);

/* Stops if needed and releases all native resources. */
void vnat_destroy(vnat_t handle);

/*
 * Bind a host-owned descriptor to a configured L3 port.
 *
 * The descriptor is borrowed: vNAT duplicates it during vnat_start, so the
 * caller keeps ownership and may close it after vnat_start returns. It must
 * remain valid for every vnat_start call. A stopped handle reuses the same
 * bindings when restarted. Call before vnat_start.
 *
 * vNAT sets O_NONBLOCK on the duplicate. Since dup() shares the open file
 * description, the original descriptor also becomes non-blocking.
 */
int vnat_set_port_fd(vnat_t handle, const char *name, int fd);

/*
 * Install a lifecycle callback. Events run on the data-plane thread. STARTED
 * is delivered before vnat_start returns. Do not call vnat_* functions other
 * than vnat_get_status from inside the callback; vnat_stop and vnat_destroy
 * would deadlock. Keep callbacks short. `message` may be NULL and is only
 * valid for the duration of the callback.
 */
int vnat_set_event_cb(vnat_t handle, vnat_event_cb callback, void *user);

/* Fill a caller-owned status snapshot. */
int vnat_get_status(vnat_t handle, vnat_status_t *status);

/* Returns a static NUL-terminated version string. */
const char *vnat_version(void);

#ifdef __cplusplus
}
#endif

#endif
