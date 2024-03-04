#pragma once

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <termios.h>

#define defer(x) __attribute__((__cleanup__(x)))

#ifndef offsetof
#define offsetof(type, member)  __builtin_offsetof (type, member)
#endif

#define container_of(ptr, type, member) ({ \
	const typeof(((type *)0)->member) *__mptr = (ptr); \
	(type *)((char *)__mptr - offsetof(type, member)); })

/* Designed to be TTY friendly */
#define RDEVMEM_MAGIC "\t\rDEVM"
#define RDEVMEM_VERSION 1
#define RDEVMEM_MAX_HANDLES 8

/* About handles
 * A handle is an identifier for a region of memory, create
 * a handle with RD_COMMAND_MMAP and close it with RD_COMMAND.
 *
 * It is up to the client to keep track of the base address associated
 * with a handle and correctly calculate the offset for read/write commands.
 */

enum rdevmem_message_type {
	RD_MESSAGE_REQUEST = 0,
	RD_MESSAGE_RESPONSE = 1,
};

/* Commands are 7 bits, the msb is the message type */
enum rdevmem_command : uint8_t {
#define RD_COMMAND_NONE 0
	RD_COMMAND_MUNMAP = 1,
	RD_COMMAND_MMAP,
	RD_COMMAND_READ,
	RD_COMMAND_WRITE,
	RD_COMMAND_HELLO = 0x24, // '$'
	RD_COMMAND_GOODBYE = 0x7E, // '~'
};

extern const char *rdevmem_command_str[];

#define RD_COMMAND_STR(command) (rdevmem_command_str[command])

enum rdevmem_status : uint8_t {
	RD_STATUS_OK = 0,
	RD_STATUS_INVALID_ARG = 1,
	RD_STATUS_INVALID_HANDLE,
	RD_STATUS_CRC_ERROR, /* Retry the request */
	RD_STATUS_OUT_OF_BOUNDS,
	RD_STATUS_WRONG_TYPE,
	RD_STATUS_INTERNAL_ERROR,
	RD_STATUS_NO_FREE_HANDLES,
	RD_STATUS_UNKNOWN_COMMAND,

	_RD_STATUS_COUNT, /* Not a real status, used for bounds checking */
};

extern const char *rdevmem_status_str[_RD_STATUS_COUNT];

#define RD_STATUS_STR(status) (rdevmem_status_str[status])

/*
 * Messages with variable length fields must have the length of the
 * field be the first entry in the command-specific part of the message.
 * it must be a uint32_t.
 */

/* RD_COMMAND_MUNMAP */
struct __attribute__((packed)) rdevmem_munmap_request {
	uint8_t handle;
};

#define RD_MUNMAP_REQUEST_LENGTH (RD_REQUEST_LENGTH + sizeof(struct rdevmem_munmap_request))
#define RD_MUNMAP_RESPONSE_LENGTH RD_RESPONSE_LENGTH

/* RD_COMMAND_MMAP */
struct __attribute__((packed)) rdevmem_mmap_request {
	uint64_t address;
	uint32_t size;
	/* flags */
	uint16_t flags;
};

struct __attribute__((packed)) rdevmem_mmap_response {
	uint8_t handle;
};

#define RD_MMAP_REQUEST_LENGTH (RD_REQUEST_LENGTH + sizeof(struct rdevmem_mmap_request))
#define RD_MMAP_RESPONSE_LENGTH (RD_RESPONSE_LENGTH + sizeof(struct rdevmem_mmap_response))


/* RD_COMMAND_READ */
struct __attribute__((packed)) rdevmem_read_request {
	uint8_t handle;
	uint32_t offset;
	uint32_t length;
};

struct __attribute__((packed)) rdevmem_read_response {
	uint32_t length;
	uint8_t data[];
};

#define RD_READ_REQUEST_LENGTH (RD_REQUEST_LENGTH + sizeof(struct rdevmem_read_request))
#define RD_READ_RESPONSE_LENGTH (RD_RESPONSE_LENGTH + offsetof(struct rdevmem_read_response, data))

/* RD_COMMAND_WRITE */
struct __attribute__((packed)) rdevmem_write_request {
	uint32_t length;
	uint8_t handle;
	uint32_t offset;
	uint8_t data[];
};

#define RD_WRITE_REQUEST_LENGTH (RD_REQUEST_LENGTH + offsetof(struct rdevmem_write_request, data))
#define RD_WRITE_RESPONSE_LENGTH RD_RESPONSE_LENGTH


/* RD_COMMAND_HELLO */
struct __attribute__((packed)) rdevmem_hello_request {
	uint8_t magic[6];
	uint8_t version;
};

struct __attribute__((packed)) rdevmem_hello_response {
	uint32_t length;
	/* Server info string */
	uint8_t info[];
};

#define RD_HELLO_REQUEST_LENGTH (RD_REQUEST_LENGTH + sizeof(struct rdevmem_hello_request))
#define RD_HELLO_RESPONSE_LENGTH (RD_RESPONSE_LENGTH + offsetof(struct rdevmem_hello_response, info))

/* Message wrappers */
struct __attribute__((packed)) rdevmem_request {
	union {
		struct rdevmem_hello_request hello;
		struct rdevmem_munmap_request munmap;
		struct rdevmem_mmap_request mmap;
		struct rdevmem_read_request read;
		struct rdevmem_write_request write;
	};
};

#define RD_REQUEST_LENGTH (RD_HEADER_LENGTH + offsetof(struct rdevmem_request, hello))

struct __attribute__((packed)) rdevmem_response {
	enum rdevmem_status status;
	union {
		struct rdevmem_hello_response hello;
		struct rdevmem_mmap_response mmap;
		struct rdevmem_read_response read;
	};
};

#define RD_RESPONSE_LENGTH (RD_HEADER_LENGTH + offsetof(struct rdevmem_response, hello))

struct __attribute__((packed)) rdevmem_message {
	uint8_t crc; /* crc8 checksum of everything below here */
	uint8_t type;
	enum rdevmem_command command;
	union {
		struct rdevmem_request request;
		struct rdevmem_response response;
	};
};

#define RD_HEADER_LENGTH offsetof(struct rdevmem_message, request)

enum rdevmem_session_type {
	RD_SESSION_STDIO,
	RD_SESSION_SOCKET,
	RD_SESSION_TTY,
};

/* Opaque library state */
struct rdevmem_session;

typedef struct rdevmem_session *rdevmem_session_t;

/* Client functions (used by host, not device under test) */

void print_hex_dump(const char *prefix, const void *buf, size_t len);

/**
 * Open an rdevmem session with a server via a socket
 *
 * @param address The address of the rdevmem server
 * @param domain The domain of the address
 * @return A session handle
 */
rdevmem_session_t rdevmem_init_socket(struct sockaddr_storage *address, int length, int domain);

/**
 * Open an rdevmem session with a server via a socket file descriptor
 *
 * @param fd The file descriptor of the socket
 * @return A session handle
 */
rdevmem_session_t rdevmem_init_socket_fd(int fd);

int _rdevmem_socket_bind(struct sockaddr_storage *address, int length, int domain);

/**
 * Open an rdevmem session with a server via a tty
 *
 * @param tty The path to the tty
 * @param baudrate The baudrate of the tty (e.g. B115200)
 * @return A session handle
 */
rdevmem_session_t rdevmem_init_tty(const char *tty, speed_t baudrate);

rdevmem_session_t rdevmem_init_stdio(void);

/**
 * Set the response timeout for a message
 *
 * @param session The session handle
 * @param timeout The timeout in milliseconds (0 for no timeout)
 */
void rdevmem_session_set_timeout(rdevmem_session_t session, uint32_t timeout);

/**
 * Set the number of retries for a message that times out or where the
 * response has an invalid CRC
 *
 * @param session The session handle
 * @param retries The number of retries
 */
void rdevmem_session_set_retries(rdevmem_session_t session, uint32_t retries);

/**
 * Close an rdevmem session
 *
 * @param session The session handle
 * @return 0 on success, -1 on error
 */
void rdevmem_session_close(rdevmem_session_t session);

/**
 * Enable or disable debug output
 *
 * @param enable 1 to enable, 0 to disable
 */
void rdevmem_debug(int enable);

/**
 * Send the hello message to the server and check the response
 *
 * @param session The session handle
 * @return enum rdevmem_status or -ve error code
 */
int rdevmem_hello(rdevmem_session_t session);

/**
 * Open a region of memory on the server
 *
 * @param session The session handle
 * @param address The base address of the region
 * @param length The length of the region
 * @return handle for the region on success or -1 on error
 */
int rdevmem_mmap(rdevmem_session_t session, uint64_t address, uint32_t length);

/**
 * Close a region of memory on the server
 *
 * @param session The session handle
 * @param handle The handle of the region
 * @return 0 on success, -1 on error
 */
int rdevmem_munmap(rdevmem_session_t session, int handle);

/**
 * Read a block of data from an address
 *
 * @param session The session handle
 * @param handle The handle of the region
 * @param offset The offset to read from
 * @param data The buffer to read into
 * @param length The length of the buffer
 * @return 0 on success, -1 on error
 */
int rdevmem_read(rdevmem_session_t session, int handle, uint32_t offset, void *data, size_t length);

/**
 * Write a block of data to an address
 *
 * @param session The session handle
 * @param handle The handle of the region
 * @param offset The offset to write to
 * @param data The buffer to write
 * @param length The length of the buffer
 * @return 0 on success, -1 on error
 */
int rdevmem_write(rdevmem_session_t session, int handle, uint32_t offset, const void *data, size_t length);

/**
 * Read a 32-bit values from an address
 *
 * @param session The session handle
 * @param handle The handle of the region
 * @param offset The offset to read from
 * @param val The value to read into
 * @return 0 on success, -1 on error
 */
static inline int rdevmem_readl(rdevmem_session_t session, int handle, uint32_t offset, uint32_t *val)
{
	return rdevmem_read(session, handle, offset, val, sizeof(*val));
}

/**
 * Write a 32-bit value to an address
 *
 * @param session The session handle
 * @param handle The handle of the region
 * @param offset The offset to write to
 * @param val The value to write
 * @return 0 on success, -1 on error
 */
static inline int rdevmem_writel(rdevmem_session_t session, int handle, uint32_t offset, uint32_t val)
{
	return rdevmem_write(session, handle, offset, &val, sizeof(val));
}

/**
 * Read an 8-bit values from an address
 *
 * @param session The session handle
 * @param handle The handle of the region
 * @param offset The offset to read from
 * @param val The value to read into
 * @return 0 on success, -1 on error
 */
static inline int rdevmem_readb(rdevmem_session_t session, int handle, uint32_t offset, uint8_t *val)
{
	return rdevmem_read(session, handle, offset, val, sizeof(*val));
}

/**
 * Write an 8-bit value to an address
 *
 * @param session The session handle
 * @param handle The handle of the region
 * @param offset The offset to write to
 * @param val The value to write
 * @return 0 on success, -1 on error
 */
static inline int rdevmem_writeb(rdevmem_session_t session, int handle, uint32_t offset, uint8_t val)
{
	return rdevmem_write(session, handle, offset, &val, sizeof(val));
}

/* Low level message handling you probably don't want to use directly */

/**
 * Send a message to a rdevmem server
 *
 * @param session File descriptor for socket or tty
 * @param type The type of session
 * @param message The message to send (the CRC field will be updated)
 * @return 0 on success, -1 on error
 */
int _rdevmem_send_message(int fd, enum rdevmem_session_type type, struct rdevmem_message *message, struct sockaddr *to, socklen_t addrlen);

/**
 * Read a message from a rdevmem server
 *
 * @param session File descriptor for socket or tty
 * @param type The type of session
 * @param message The message to read into
 * @return 0 on success, -1 on error
 */
int _rdevmem_read_data(int fd, enum rdevmem_session_type type, void *data, size_t length);

int _rdevmem_read_data_from(int fd, enum rdevmem_session_type type, void *data, size_t max_length, struct sockaddr_storage *from);

/**
 * Receive a message from a rdevmem server
 *
 * @param session The session handle
 * @param err A pointer to an int to store the error code (set on failure)
 * @return The message received or NULL on failure
 *
 * This function allocates memory for the message, the caller is
 * responsible for calling free() on the returned message.
 */
struct rdevmem_message *rdevmem_receive_response(rdevmem_session_t session, int *err);

/**
 * Send a message to a rdevmem server and wait for a response
 *
 * @param session The session handle
 * @param message The message to send (the CRC field will be updated)
 * @param err A pointer to an int to store the error code (set on failure)
 * @return The response received or NULL on failure
 *
 * This function allocates memory for the response, the caller is
 * responsible for calling free() on the returned response.
 */
struct rdevmem_response *rdevmem_message_roundtrip(rdevmem_session_t session, struct rdevmem_message *message, int *err);

/**
 * Free a message
 *
 * @param response The message to free
 */
void rdevmem_free_response(struct rdevmem_response **response);

/**
 * Calculate the length of a message
 *
 * @param message The message to calculate the length of
 * @param available_length The current length of the message
 * @return The length of the message in bytes
 *
 * rdevmem messages don't all have a fixed length, and due to the
 * implementation relying on packed structs, we don't need to
 * encode the length of the message in the message itself.
 *
 * Whatever transport layer is used will handle this, but we do
 * need to know the length of the message to send it.
 */
ssize_t rdevmem_message_length(const struct rdevmem_message *message, int available_length);

#define RD_MESSAGE_AVAILABLE 0x7FFFFFFF

/**
 * Calculate the crc of a message and update the crc field
 *
 * @param message The message to calculate the crc of
 * @return A const pointer to the same message with the crc field updated
 *
 * After the CRC is set, the message should not be modified. As good practise
 * the returned const pointer can be used to ensure this.
 */
const struct rdevmem_message *rdevmem_message_crc(struct rdevmem_message *message);

/**
 * Validate the crc of a message
 *
 * @param message The message to validate
 * @return 0 on success, -1 on error
 */
int rdevmem_message_validate_crc(const struct rdevmem_message *message);
