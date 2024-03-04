// SPDX-License-Identifier: GPL-2.0
/*
 * Remote devmem Linux server implementation.
 *
 * Copyright (C) 2024 Linaro Ltd.
 *   Author: Caleb Connolly <caleb.connolly@linaro.org>
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/un.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "rdevmem.h"
#include "sys/mman.h"

#define zalloc(size) calloc(1, size)

#define HANDLE_INDEX_START 100

struct handle {
	void *addr;
	size_t length;
};

static struct {
	int connection_fd;
	int devmem_fd;
	enum rdevmem_session_type type;
	struct handle handles[RDEVMEM_MAX_HANDLES];
	const char *devmem_path;
} rdvm = { 0 };

static void usage()
{
	fprintf(stderr, "Usage: rdevmem <-s|-t> [OPTIONS]... [address [value]]\n");
	fprintf(stderr, "Remote devmem server and demo client.\n");
	fprintf(stderr, "For client mode, specify the address and value to write.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "  -h, --help\t\t\tDisplay this help and exit\n");
	fprintf(stderr, "  -v, --version\t\t\tOutput version information and exit\n");
	fprintf(stderr, "  -s, --socket=PATH\t\tPath to the socket file\n");
	fprintf(stderr, "  -t, --tty=PATH\t\t\tPath to the tty device\n");
	fprintf(stderr, "  -d, --devmem=PATH\t\tPath to the devmem device\n");
	fprintf(stderr, "\n");
}

static int alloc_handle(void *addr, size_t length)
{
	int i;
	for (i = HANDLE_INDEX_START; i < HANDLE_INDEX_START + RDEVMEM_MAX_HANDLES; i++) {
		if (!rdvm.handles[i - HANDLE_INDEX_START].addr) {
			rdvm.handles[i - HANDLE_INDEX_START].addr = addr;
			rdvm.handles[i - HANDLE_INDEX_START].length = length;
			return i;
		}
	}
	return -1;
}

static struct handle *get_handle(int handle)
{
	handle -= HANDLE_INDEX_START;
	if (handle >= RDEVMEM_MAX_HANDLES)
		return NULL;
	return &rdvm.handles[handle];
}

static void free_handle(int handle)
{
	struct handle *h = get_handle(handle);
	if (h) {
		if (munmap(h->addr, h->length) < 0)
			fprintf(stderr, "Failed to munmap handle %d (%#lx)\n", handle, (uint64_t)h->addr);

		h->addr = NULL;
		h->length = 0;
	}
}

static int respond_error(struct rdevmem_message *message, enum rdevmem_status status)
{
	memset(message, 0, RD_HEADER_LENGTH);
	message->type = RD_MESSAGE_RESPONSE;
	message->response.status = status;
	return _rdevmem_send_message(rdvm.connection_fd, rdvm.type, message, NULL, 0);
}

static int validate_request(struct rdevmem_message *message)
{
	/* If the CRC is wrong return an error */
	if (rdevmem_message_validate_crc(message) < 0) {
		fprintf(stderr, "Invalid CRC in request!\n");
		memset(message, 0, RD_HEADER_LENGTH);
		message->type = RD_MESSAGE_RESPONSE;
		message->response.status = RD_STATUS_CRC_ERROR;
		_rdevmem_send_message(rdvm.connection_fd, rdvm.type, message, NULL, 0);
		return -1;
	}

	if (message->type != RD_MESSAGE_REQUEST) {
		fprintf(stderr, "Invalid message type!\n");
		respond_error(message, RD_STATUS_WRONG_TYPE);
		return -1;
	}

	return 0;
}

static int process_mmap(struct rdevmem_request *request, struct rdevmem_response *response)
{
	int handle;
	void *addr;
	size_t length = (request->mmap.size + 0xfff) & ~0xfff;
	off_t offset = request->mmap.address & ~0xfff;

	fprintf(stderr, "mmap: %#lx, %#lx (req %#lx, %#x)\n",offset, length, request->mmap.address, request->mmap.size);

	addr = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, rdvm.devmem_fd, offset);
	if (addr == MAP_FAILED) {
		fprintf(stderr, "Failed to mmap\n");
		response->status = RD_STATUS_INTERNAL_ERROR;
		return -1;
	}

	handle = alloc_handle(addr, length);
	if (handle < 0) {
		fprintf(stderr, "Failed to allocate handle\n");
		response->status = RD_STATUS_NO_FREE_HANDLES;
		return 0;
	}

	response->mmap.handle = handle;

	response->status = RD_STATUS_OK;
	return 0;
}

static int process_munmap(struct rdevmem_request *request, struct rdevmem_response *response)
{
	struct handle *handle = get_handle(request->munmap.handle);
	if (!handle) {
		fprintf(stderr, "Invalid handle\n");
		response->status = RD_STATUS_INVALID_HANDLE;
		return -1;
	}

	free_handle(request->munmap.handle);

	response->status = RD_STATUS_OK;
	return 0;
}

static int process_read(struct rdevmem_request *request, struct rdevmem_response *response)
{
	struct handle *handle = get_handle(request->read.handle);
	void *data;
	if (!handle) {
		fprintf(stderr, "Invalid handle\n");
		response->status = RD_STATUS_INVALID_HANDLE;
		return -1;
	}

	fprintf(stderr, "read: handle %d (%#lx), %#x, %#x bytes\n", request->read.handle, (uint64_t)handle->addr, request->read.offset, request->read.length);
	fprintf(stderr, "read: %s\n", (char *)(handle->addr + request->read.offset));

	// FIXME: detect out of bounds!

	data = memcpy((void*)response->read.data, handle->addr + request->read.offset, request->read.length);
	if (!data) {
		fprintf(stderr, "Failed to read from memory %s\n", strerror(errno));
		response->status = RD_STATUS_INTERNAL_ERROR;
		return -1;
	}

	response->read.length = request->read.length;
	response->status = RD_STATUS_OK;
	return 0;
}

static int process_write(struct rdevmem_request *request, struct rdevmem_response *response)
{
	struct handle *handle = get_handle(request->write.handle);
	void *data;
	if (!handle) {
		fprintf(stderr, "Invalid handle\n");
		response->status = RD_STATUS_INVALID_HANDLE;
		return -1;
	}

	data = memcpy(handle->addr + request->write.offset, &request->write.data, request->write.length);
	if (!data) {
		fprintf(stderr, "Failed to write to memory %s\n", strerror(errno));
		response->status = RD_STATUS_INTERNAL_ERROR;
		return -1;
	}

	response->status = RD_STATUS_OK;
	return 0;
}

static int process_request(enum rdevmem_command command, struct rdevmem_request *request, struct rdevmem_message **response_message)
{
	*response_message = zalloc(1024);
	static const char *server_info = "rdevmem reference server v%d";
	(*response_message)->type = RD_MESSAGE_RESPONSE;
	/* Response messages should always have command set to 0 */
	(*response_message)->command = command;

	struct rdevmem_response *response = &(*response_message)->response;

	fprintf(stderr, "Got request: %s\n", RD_COMMAND_STR(command));

	switch (command) {
	case RD_COMMAND_HELLO:
		snprintf((char *)response->hello.info, strlen(server_info), server_info, RDEVMEM_VERSION);
		response->hello.length = strlen(server_info);
		response->status = RD_STATUS_OK;
		break;
	case RD_COMMAND_MMAP:
		process_mmap(request, response);
		break;
	case RD_COMMAND_MUNMAP:
		process_munmap(request, response);
		break;
	case RD_COMMAND_READ:
		process_read(request, response);
		break;
	case RD_COMMAND_WRITE:
		process_write(request, response);
	case RD_COMMAND_GOODBYE:
		response->status = RD_STATUS_OK;
		break;
	default:
		fprintf(stderr, "Unknown command\n");
		response->status = RD_STATUS_UNKNOWN_COMMAND;
		return -1;
	}

	if (response->status != RD_STATUS_OK)
		fprintf(stderr, "Responded with error: %s\n", RD_STATUS_STR(response->status));

	return 0;
}

static int server_main_loop()
{
	struct rdevmem_message *message = zalloc(1024);
	size_t max_message_length = 1024;
	int ret;

	rdvm.devmem_fd = open(rdvm.devmem_path, O_RDWR | O_SYNC);
	if (rdvm.devmem_fd < 0) {
		fprintf(stderr, "open devmem\n");
		return 1;
	}

	fprintf(stderr, "Server running\n");
	while (1) {
		struct rdevmem_message *response;
		struct sockaddr_un from = { 0 };
		struct pollfd fds[1];
		fds[0].fd = rdvm.connection_fd;
		fds[0].events = POLLIN;

		ret = poll(fds, 1, -1);
		if (ret < 0) {
			fprintf(stderr, "poll\n");
			return 1;
		}
		if (!ret) {
			fprintf(stderr, "No message\n");
			continue;
		}
		if (!(fds[0].revents & POLLIN))
			continue;

		memset(message, 0, max_message_length);

		ret = _rdevmem_read_data_from(rdvm.connection_fd, rdvm.type, message, max_message_length, (struct sockaddr_storage*)&from);
		if (ret < 0) {
			fprintf(stderr, "failed to read message\n");
			return 1;
		}

		if (validate_request(message) < 0)
			continue;

		if (process_request(message->command, &message->request, &response) < 0)
			continue;

		if (_rdevmem_send_message(rdvm.connection_fd, rdvm.type, response, (struct sockaddr*)&from, sizeof(struct sockaddr_un)) < 0) {
			fprintf(stderr, "Failed to send hello response\n");
			return -1;
		}
	}
}

static int client_do(uint64_t address, uint32_t value, bool write)
{
	rdevmem_session_t session;
	int error, handle;

	if (rdvm.type == RD_SESSION_STDIO) {
		session = rdevmem_init_stdio();
	} else if (rdvm.type == RD_SESSION_SOCKET) {
		session = rdevmem_init_socket_fd(rdvm.connection_fd);
	} else {
		fprintf(stderr, "Unknown session type\n");
		return 1;
	}

	error = rdevmem_hello(session);
	if (error < 0) {
		fprintf(stderr, "Failed to send hello\n");
		return 1;
	}

	handle = rdevmem_mmap(session, address, sizeof(value));
	if (handle < 0) {
		fprintf(stderr, "Failed to mmap memory\n");
		return 1;
	}

	if (write) {
		error = rdevmem_write(session, handle, 0, &value, sizeof(value));
		if (error < 0) {
			fprintf(stderr, "Failed to write to memory\n");
			return 1;
		}
	} else {
		error = rdevmem_read(session, handle, 0, &value, sizeof(value));
		if (error < 0) {
			fprintf(stderr, "Failed to read from memory\n");
			return 1;
		}
		fprintf(stderr, "0x%08x\n", value);
	}

	return 0;
}

int main(int argc, char *const argv[])
{
	int opt;
	bool server = true, write = false;
	uint64_t address = 0;
	uint32_t value = 0;
	struct sockaddr_un addr = { 0 }, addr_client = { 0 };

	rdvm.devmem_path = "/dev/mem";

	rdevmem_debug(true);

	while (1) {
		static struct option long_options[] = { { "help", no_argument, 0, 'h' },
							{ "version", no_argument, 0, 'v' },
							{ "socket", required_argument, 0, 's' },
							{ "tty", required_argument, 0, 't' },
							{ "devmem", required_argument, 0, 'd'},
							{ 0, 0, 0, 0 } };

		opt = getopt_long(argc, argv, "hvs:t:d:", long_options, NULL);

		if (opt == -1)
			break;

		switch (opt) {
		case 'h':
			usage();
			return 0;
		case 'v':
			fprintf(stderr, "rdevmem %d\n", RDEVMEM_VERSION);
			return 0;
		case 's': {
			addr.sun_family = AF_UNIX;
			strncpy(addr.sun_path, optarg, sizeof(addr.sun_path) - 1);
			break;
		}
		case 't':
			fprintf(stderr, "tty not implemented");
			return 1;
			break;
		case 'd':
			rdvm.devmem_path = optarg;
			break;
		default:
			usage();
			return 1;
		}
	}

	if (optind < argc)
		server = false;

#define CLIENT_SUFFIX ".client"
	if (rdvm.type == RD_SESSION_STDIO && addr.sun_family == AF_UNIX) {
		if (!server) {
			addr_client.sun_family = AF_UNIX;
			strncpy(addr_client.sun_path, addr.sun_path, sizeof(addr_client.sun_path) - 1);
			strncat(addr_client.sun_path, CLIENT_SUFFIX, sizeof(addr_client.sun_path) - 1);
			unlink(addr_client.sun_path);

			rdvm.connection_fd = _rdevmem_socket_bind((struct sockaddr_storage *)&addr_client, sizeof(addr_client), PF_UNIX);
			if (rdvm.connection_fd < 0) {
				fprintf(stderr, "failed to bind socket %s\n", addr_client.sun_path);
				return 1;
			}
			fprintf(stderr, "Bound to %s\n", addr_client.sun_path);
		} else {
			unlink(addr.sun_path);

			rdvm.connection_fd = _rdevmem_socket_bind((struct sockaddr_storage *)&addr, sizeof(addr), PF_UNIX);
			if (rdvm.connection_fd < 0) {
				fprintf(stderr, "failed to bind socket %s\n", addr.sun_path);
				return 1;
			}
			fprintf(stderr, "Bound to %s\n", addr.sun_path);
		}

		rdvm.type = RD_SESSION_SOCKET;
	}

	if (optind < argc) {
		address = strtoull(argv[optind++], NULL, 0);
		if (optind < argc) {
			write = true;
			value = strtoul(argv[optind++], NULL, 0);
		}
		if (addr.sun_family && connect(rdvm.connection_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr)) < 0) {
			fprintf(stderr, "couldn't connect to server '%s': %s\n", addr.sun_path, strerror(errno));
			return 1;
		}
		return client_do(address, value, write);
	} else {
		return server_main_loop();
	}
}
