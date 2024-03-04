// SPDX-License-Identifier: GPL-2.0
/*
 * Remove devmem library
 *
 * Copyright (C) 2024 Linaro Ltd.
 *   Author: Caleb Connolly <caleb.connolly@linaro.org>
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <unistd.h>

#define _GNU_SOURCE
#include <sys/mman.h>

#include "rdevmem.h"

#define zalloc(size) calloc(1, size)

static bool debug = false;

#define log_error(fmt, ...) fprintf(stderr, "[ERROR] rdevmem: " fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) fprintf(stderr, "[INFO] rdevmem: " fmt, ##__VA_ARGS__)
#define log_debug(fmt, ...) \
	if (debug)          \
	fprintf(stderr, "[DEBUG] rdevmem: " fmt, ##__VA_ARGS__)

#define BUF_SIZE 4096

struct rdevmem_session {
	int fd;
	enum rdevmem_session_type type;
	uint32_t timeout; /* in milliseconds */
	int retries;
	int last_message_size;
	uint8_t buf[BUF_SIZE];
};

static inline struct rdevmem_message *message_alloc(rdevmem_session_t session)
{
	memset(session->buf, 0, session->last_message_size);
	session->last_message_size = 0;

	return (void*)session->buf;
}

void rdevmem_debug(int enable)
{
	debug = !!enable;
}

int _rdevmem_socket_bind(struct sockaddr_storage *address, int length, int domain)
{
	int fd = socket(domain, SOCK_DGRAM, 0);
	int error;
	if (fd < 0) {
		log_error("Failed to create socket\n");
		return -1;
	}

	if ((error = bind(fd, (struct sockaddr *)address, length)) < 0) {
		log_error("Failed to bind socket: %d\n", errno);
		close(fd);
		return -1;
	}

	return fd;
}

rdevmem_session_t rdevmem_init_socket_fd(int fd)
{
	rdevmem_session_t session = zalloc(sizeof(struct rdevmem_session));

	session->type = RD_SESSION_SOCKET;
	session->fd = fd;

	return session;
}

rdevmem_session_t rdevmem_init_stdio(void)
{
	rdevmem_session_t session = zalloc(sizeof(struct rdevmem_session));

	session->type = RD_SESSION_STDIO;

	return session;
}

rdevmem_session_t rdevmem_init_socket(struct sockaddr_storage *address, int length, int domain)
{
	int fd = _rdevmem_socket_bind(address, length, domain);
	if (fd < 0)
		return NULL;

	if (connect(fd, (struct sockaddr *)address, length) < 0) {
		log_error("Failed to connect to socket\n");
		close(fd);
		return NULL;
	}

	return rdevmem_init_socket_fd(fd);
}

rdevmem_session_t rdevmem_init_tty(const char *path, speed_t speed)
{
	rdevmem_session_t session = zalloc(sizeof(struct rdevmem_session));
	struct termios tty;

	session->type = RD_SESSION_TTY;
	session->fd = open(path, O_RDWR | O_NOCTTY | O_NDELAY);
	if (session->fd < 0) {
		log_error("Failed to open tty\n");
		free(session);
		return NULL;
	}

	if (tcgetattr(session->fd, &tty) < 0) {
		log_error("Failed to get tty attributes\n");
		close(session->fd);
		free(session);
		return NULL;
	}

	cfsetospeed(&tty, speed);

	if (tcsetattr(session->fd, TCSANOW, &tty) < 0) {
		log_error("Failed to set tty attributes\n");
		close(session->fd);
		free(session);
		return NULL;
	}

	return session;
}

void rdevmem_session_close(rdevmem_session_t session)
{
	struct rdevmem_message message = {
		.type = RD_MESSAGE_REQUEST,
		.command = RD_COMMAND_GOODBYE,
	};

	_rdevmem_send_message(session->fd, session->type, &message, NULL, 0);

	close(session->fd);
	free(session);
}

void rdevmem_session_set_timeout(rdevmem_session_t session, uint32_t timeout)
{
	session->timeout = timeout;
}

void rdevmem_session_set_retries(rdevmem_session_t session, uint32_t retries)
{
	session->retries = retries;
}

int _rdevmem_send_message(int fd, enum rdevmem_session_type type, struct rdevmem_message *message, struct sockaddr *to, socklen_t addrlen)
{
	ssize_t message_length;
	int ret;

	message_length = rdevmem_message_length(message, RD_MESSAGE_AVAILABLE);
	if (message_length < 0) {
		log_error("Failed to get message size\n");
		return -1;
	}

	rdevmem_message_crc(message);

	// printf("Sending %s message (%ld bytes)\n", RD_COMMAND_STR(message->command), message_length);
	// print_hex_dump(NULL, message, message_length);

	switch (type) {
	case RD_SESSION_SOCKET:
		if (to) {
			ret = sendto(fd, message, message_length, 0, to, addrlen);
		} else {
		 	ret = send(fd, message, message_length, 0);
		}
		if (ret < 0) {
			log_error("Failed to send message\n");
			return -1;
		}
		printf("Sent message to socket\n");
		break;
	case RD_SESSION_TTY:
		if (write(fd, message, message_length) < 0) {
			log_error("Failed to write message\n");
			return -1;
		}
		tcflush(fd, TCOFLUSH);
		break;
	case RD_SESSION_STDIO:
		if (fwrite(message, message_length, 1, stdout) < 0) {
			log_error("Failed to write message\n");
			return -1;
		}
		fflush(stdout);
		break;
	default:
		fprintf(stderr, "Invalid session type %d\n", type);
		return -1;
	}

	return 0;
}

int _rdevmem_read_data_from(int fd, enum rdevmem_session_type type, void *data, size_t max_length, struct sockaddr_storage *from)
{
	ssize_t length_read;

	switch (type) {
	case RD_SESSION_SOCKET:
		length_read = recv(fd, NULL, 0, MSG_PEEK | MSG_TRUNC);
		if (length_read < 0) {
			log_error("Failed to receive data: %s\n", strerror(errno));
			return -1;
		}
		socklen_t addrlen = sizeof(struct sockaddr_storage);
		length_read = recvfrom(fd, data, length_read, 0, (struct sockaddr*)from, &addrlen);
		if (length_read < 0) {
			log_error("Failed to receive data: %s\n", strerror(errno));
			return -1;
		}
		break;
	case RD_SESSION_TTY:
		// FIXME: probably borked
		length_read = read(fd, data, max_length);
		if (length_read < 0)
			return -1;
		break;
	case RD_SESSION_STDIO:
		length_read = fread(data, 1, max_length, stdin);
		if (length_read < 0)
			return -1;
		break;
	default:
		fprintf(stderr, "Invalid session type %d\n", type);
		return -1;
	}

	print_hex_dump("Received data", data, length_read);

	return length_read;
}

int _rdevmem_read_data(int fd, enum rdevmem_session_type type, void *data, size_t max_length)
{
	return _rdevmem_read_data_from(fd, type, data, max_length, NULL);
}

struct rdevmem_message *rdevmem_receive_response(rdevmem_session_t session, int *err)
{
	/* Initially allocate enough for any of the fixed size responses */
	struct rdevmem_message *message = message_alloc(session);
	int ret;

	ret = _rdevmem_read_data(session->fd, session->type, message, BUF_SIZE);
	if (ret < 0) {
		log_error("Failed to read message\n");
		*err = -1;
		free(message);
		return NULL;
	}
	session->last_message_size = ret;

	if (rdevmem_message_validate_crc(message) < 0) {
		log_error("Invalid message CRC\n");
		*err = -1;
		return NULL;
	}

	*err = 0;
	return message;
}

struct rdevmem_response *rdevmem_message_roundtrip(rdevmem_session_t session,
						   struct rdevmem_message *message, int *err)
{
	int error, try = 0;
	struct rdevmem_message *response = NULL;

	for (; try <= session->retries; try++) {
		if (try > 1)
			log_info("Retrying message (try %d/%d)\n", try, session->retries);

		error = _rdevmem_send_message(session->fd, session->type, message, NULL, 0);
		if (error < 0) {
			*err = -1;
			/* FIXME: is there a situation we might want to retry on failure here? */
			return NULL;
		}

		response = rdevmem_receive_response(session, err);
		if (!response)
			continue;

		if (rdevmem_message_validate_crc(response) < 0) {
			log_error("Invalid response CRC\n");
			*err = -1;
			continue;
		}

		if (response->response.status == RD_STATUS_CRC_ERROR) {
			log_info("Server requested retry\n");
			continue;
		}
	}

	if (!response) {
		log_error("Failed to receive response\n");
		*err = -1;
		return NULL;
	}

	if (try == session->retries) {
		log_error("Failed to receive response after %d tries\n", session->retries);
		*err = -1;
		free(response);
		return NULL;
	}

	*err = 0;
	return &response->response;
}

void rdevmem_free_response(struct rdevmem_response **response)
{
	struct rdevmem_message *message = container_of(*response, struct rdevmem_message, response);
	if (!*response)
		return;

	log_info("Freeing message (type %d cmd %d)\n", message->type, message->command);
	free(message);
}

/* message wrappers */

int rdevmem_hello(rdevmem_session_t session)
{
	int error;
	/* The hello message is a fixed size and can be safely allocated on the stack */
	struct rdevmem_message message = { .type = RD_MESSAGE_REQUEST,
					   .command = RD_COMMAND_HELLO,
					   .request.hello = {
						   .magic = RDEVMEM_MAGIC,
						   .version = RDEVMEM_VERSION,
					   } };
	struct rdevmem_response *response;

	response = rdevmem_message_roundtrip(session, &message, &error);
	if (!response)
		return -1;

	if (response->status != RD_STATUS_OK) {
		log_error("Server responded with error: %s\n", RD_STATUS_STR(response->status));
		return response->status;
	}

	log_debug("Connected! Server info:\n\t%.*s\n", response->hello.length,
			response->hello.info);

	return 0;
}

int rdevmem_mmap(rdevmem_session_t session, uint64_t address, uint32_t length)
{
	int error;
	struct rdevmem_message message = { .type = RD_MESSAGE_REQUEST,
					   .command = RD_COMMAND_MMAP,
					   .request.mmap = {
						   .address = address,
						   .size = length,
					   } };

	struct rdevmem_response *response;

	response = rdevmem_message_roundtrip(session, &message, &error);
	if (!response)
		return -1;

	if (response->status != RD_STATUS_OK) {
		log_error("Server responded with error: %d\n", response->status);
		return response->status;
	}

	log_debug("Mapped address 0x%lx\n", address);

	return response->mmap.handle;
}

int rdevmem_munmap(rdevmem_session_t session, int handle)
{
	int error;
	struct rdevmem_message message = { .type = RD_MESSAGE_REQUEST,
					   .command = RD_COMMAND_MUNMAP,
					   .request.munmap = {
						   .handle = handle,
					   } };

	struct rdevmem_response *response;

	response = rdevmem_message_roundtrip(session, &message, &error);
	if (!response)
		return -1;

	if (response->status != RD_STATUS_OK) {
		log_error("Server responded with error: %d\n", response->status);
		return response->status;
	}

	log_debug("Unmapped handle %d\n", handle);

	return 0;
}

int rdevmem_read(rdevmem_session_t session, int handle, uint32_t offset, void *data, size_t length)
{
	int error;
	struct rdevmem_message message = { .type = RD_MESSAGE_REQUEST,
					   .command = RD_COMMAND_READ,
					   .request.read = {
						   .handle = handle,
						   .offset = offset,
						   .length = length,
					   } };

	struct rdevmem_response *response;

	response = rdevmem_message_roundtrip(session, &message, &error);
	if (!response)
		return -1;

	if (response->status != RD_STATUS_OK) {
		log_error("Server responded with error: %d\n", response->status);
		return response->status;
	}

	if (length != response->read.length) {
		log_error("Expected %lu bytes but received %u instead!\n", length,
				response->read.length);
		return -1;
	}

	memcpy(data, response->read.data, length);

	return 0;
}

int rdevmem_write(rdevmem_session_t session, int handle, uint32_t offset, const void *data,
		  size_t length)
{
	int error;
	struct rdevmem_message *message = zalloc(RD_WRITE_REQUEST_LENGTH + length);
	if (!message) {
		log_error("Failed to realloc message\n");
		return -1;
	}

	message->type = RD_MESSAGE_REQUEST;
	message->command = RD_COMMAND_WRITE;
	message->request.write.handle = handle;
	message->request.write.offset = offset;
	message->request.write.length = length;

	memcpy(message->request.write.data, data, length);

	struct rdevmem_response *response;

	response = rdevmem_message_roundtrip(session, message, &error);
	if (!response)
		return -1;

	if (response->status != RD_STATUS_OK) {
		log_error("Server responded with error: %d\n", response->status);
		return response->status;
	}

	log_debug("Wrote %lu bytes to handle %d\n", length, handle);

	return 0;
}

ssize_t rdevmem_message_length(const struct rdevmem_message *message, int available_length)
{
	ssize_t size;

	switch (message->type) {
	case RD_MESSAGE_REQUEST:
		size = RD_REQUEST_LENGTH;
		switch (message->command) {
		case RD_COMMAND_HELLO:
			size += sizeof(struct rdevmem_hello_request);
			break;
		case RD_COMMAND_MUNMAP:
			size += sizeof(struct rdevmem_munmap_request);
			break;
		case RD_COMMAND_MMAP:
			size += sizeof(struct rdevmem_mmap_request);
			break;
		case RD_COMMAND_READ:
			size += sizeof(struct rdevmem_read_request);
			break;
		case RD_COMMAND_WRITE:
			if (available_length < RD_WRITE_REQUEST_LENGTH)
				return -EAGAIN; /* Request that more data be read */
			size += sizeof(struct rdevmem_write_request);
			size += message->request.write.length;
			break;
		case RD_COMMAND_GOODBYE:
			break;
		}

		break;
	case RD_MESSAGE_RESPONSE:
		size = RD_RESPONSE_LENGTH;
		switch (message->command) {
		case RD_COMMAND_HELLO:
			size += sizeof(struct rdevmem_hello_response);
			size += message->response.hello.length;
			break;
		case RD_COMMAND_MMAP:
			size += sizeof(struct rdevmem_mmap_response);
			break;
		case RD_COMMAND_READ:
			if (available_length < RD_READ_RESPONSE_LENGTH)
				return -EAGAIN; /* Request that more data be read */
			size += sizeof(struct rdevmem_read_response);
			size += message->response.read.length;
			break;
		/* Empty responses */
		case RD_COMMAND_MUNMAP:
		case RD_COMMAND_WRITE:
		case RD_COMMAND_GOODBYE:
			break;
		}
		break;
	}

	return size;
}

static unsigned char const crc8x_table[] = {
	0x00, 0x31, 0x62, 0x53, 0xc4, 0xf5, 0xa6, 0x97, 0xb9, 0x88, 0xdb, 0xea, 0x7d, 0x4c, 0x1f,
	0x2e, 0x43, 0x72, 0x21, 0x10, 0x87, 0xb6, 0xe5, 0xd4, 0xfa, 0xcb, 0x98, 0xa9, 0x3e, 0x0f,
	0x5c, 0x6d, 0x86, 0xb7, 0xe4, 0xd5, 0x42, 0x73, 0x20, 0x11, 0x3f, 0x0e, 0x5d, 0x6c, 0xfb,
	0xca, 0x99, 0xa8, 0xc5, 0xf4, 0xa7, 0x96, 0x01, 0x30, 0x63, 0x52, 0x7c, 0x4d, 0x1e, 0x2f,
	0xb8, 0x89, 0xda, 0xeb, 0x3d, 0x0c, 0x5f, 0x6e, 0xf9, 0xc8, 0x9b, 0xaa, 0x84, 0xb5, 0xe6,
	0xd7, 0x40, 0x71, 0x22, 0x13, 0x7e, 0x4f, 0x1c, 0x2d, 0xba, 0x8b, 0xd8, 0xe9, 0xc7, 0xf6,
	0xa5, 0x94, 0x03, 0x32, 0x61, 0x50, 0xbb, 0x8a, 0xd9, 0xe8, 0x7f, 0x4e, 0x1d, 0x2c, 0x02,
	0x33, 0x60, 0x51, 0xc6, 0xf7, 0xa4, 0x95, 0xf8, 0xc9, 0x9a, 0xab, 0x3c, 0x0d, 0x5e, 0x6f,
	0x41, 0x70, 0x23, 0x12, 0x85, 0xb4, 0xe7, 0xd6, 0x7a, 0x4b, 0x18, 0x29, 0xbe, 0x8f, 0xdc,
	0xed, 0xc3, 0xf2, 0xa1, 0x90, 0x07, 0x36, 0x65, 0x54, 0x39, 0x08, 0x5b, 0x6a, 0xfd, 0xcc,
	0x9f, 0xae, 0x80, 0xb1, 0xe2, 0xd3, 0x44, 0x75, 0x26, 0x17, 0xfc, 0xcd, 0x9e, 0xaf, 0x38,
	0x09, 0x5a, 0x6b, 0x45, 0x74, 0x27, 0x16, 0x81, 0xb0, 0xe3, 0xd2, 0xbf, 0x8e, 0xdd, 0xec,
	0x7b, 0x4a, 0x19, 0x28, 0x06, 0x37, 0x64, 0x55, 0xc2, 0xf3, 0xa0, 0x91, 0x47, 0x76, 0x25,
	0x14, 0x83, 0xb2, 0xe1, 0xd0, 0xfe, 0xcf, 0x9c, 0xad, 0x3a, 0x0b, 0x58, 0x69, 0x04, 0x35,
	0x66, 0x57, 0xc0, 0xf1, 0xa2, 0x93, 0xbd, 0x8c, 0xdf, 0xee, 0x79, 0x48, 0x1b, 0x2a, 0xc1,
	0xf0, 0xa3, 0x92, 0x05, 0x34, 0x67, 0x56, 0x78, 0x49, 0x1a, 0x2b, 0xbc, 0x8d, 0xde, 0xef,
	0x82, 0xb3, 0xe0, 0xd1, 0x46, 0x77, 0x24, 0x15, 0x3b, 0x0a, 0x59, 0x68, 0xff, 0xce, 0x9d,
	0xac
};

const struct rdevmem_message *rdevmem_message_crc(struct rdevmem_message *msg)
{
	unsigned char crc = 0;
	/* The crc byte is the first byte in the message, skip it */
	unsigned char *data = (unsigned char *)msg + 1;
	size_t length = rdevmem_message_length(msg, RD_MESSAGE_AVAILABLE);

	for (size_t i = 0; i < length; i++)
		crc = crc8x_table[crc ^ data[i]];

	msg->crc = crc;
	return msg;
}

int rdevmem_message_validate_crc(const struct rdevmem_message *msg)
{
	unsigned char crc = 0;
	unsigned char *data = (unsigned char *)msg + 1;
	size_t length = rdevmem_message_length(msg, RD_MESSAGE_AVAILABLE);

	for (size_t i = 0; i < length; i++)
		crc = crc8x_table[crc ^ data[i]];

	return crc == msg->crc ? 0 : -1;
}

const char *rdevmem_command_str[] = {
	[RD_COMMAND_NONE] = "NONE", /* Not a valid command */
	[RD_COMMAND_MUNMAP] = "MUNMAP",
	[RD_COMMAND_MMAP] = "MMAP",
	[RD_COMMAND_READ] = "READ",
	[RD_COMMAND_WRITE] = "WRITE",
	[RD_COMMAND_HELLO] = "HELLO",
	[RD_COMMAND_GOODBYE] = "GOODBYE",
};

const char *rdevmem_status_str[_RD_STATUS_COUNT] = {
	"OK",
	"Invalid argument",
	"Invalid handle",
	"CRC error",
	"Out of bounds access",
	"Invalid message type",
	"Internal error",
	"No free handles",
	"Unknown command",
};

static_assert(sizeof(rdevmem_status_str) / sizeof(rdevmem_status_str[0]) == _RD_STATUS_COUNT,
	      "rdevmem_status_str must match the number of status codes");

static char to_hex(uint8_t ch)
{
	ch &= 0xf;
	return ch <= 9 ? '0' + ch : 'A' + ch - 10;
}

#define LINE_LENGTH 32
#define MIN(x, y) ((x) < (y) ? (x) : (y))

void print_hex_dump(const char *prefix, const void *buf, size_t len)
{
	const uint8_t *ptr = buf;
	size_t linelen, buf_size;
	uint8_t ch;
	int i;
	int j;
	char *printbuf;
	if (!debug)
		return;
	FILE *fp = open_memstream(&printbuf, &buf_size);

	// if (len < 0) {
	// 	LOGW("%s: len %zu less than 0", __func__, len);
	// 	return;
	// }

	if (prefix)
		fprintf(fp, "%s:\n", prefix);

	for (i = 0; i < len; i += LINE_LENGTH) {
		linelen = MIN(LINE_LENGTH, len - i);

		for (j = 0; j < linelen; j++) {
			ch = ptr[i + j];
			fprintf(fp, "%c", to_hex(ch >> 4));
			fprintf(fp, "%c", to_hex(ch));
			fprintf(fp, "%c", j < linelen - 1 ? ':' : ' ');
		}

		for (; j < LINE_LENGTH; j++) {
			fprintf(fp, "%c", ' ');
			fprintf(fp, "%c", ' ');
			fprintf(fp, "%c", ' ');
		}

		for (j = 0; j < linelen; j++) {
			ch = ptr[i + j];
			fprintf(fp, "%c", isprint(ch) ? ch : '.');
		}

		fprintf(fp, "\n");
	}

	fclose(fp);
	fprintf(stderr, "%s", printbuf);
	free(printbuf);
}
