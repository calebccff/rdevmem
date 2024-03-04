# rdevmem

rdevmem is a tool/library for interacting with embedded devices. In short, it
proxies `/dev/mem` over a UNIX or INET socket, tty, or regular ol' stdio. This
way, it can be used to build fancy debugging tools (with GUIs!) that run on your
host rather than on your target device. It also means your tools don't need to
be cross compiled.

> [!NOTE] rdevmem is still very work in progress and needs a lot of polish.
> However the API is unlikely to change. TTY support is not yet implemented and
> there are likely many bugs in the protocol still.

The rdevmem library provides a simple high level API for interacting with
`/dev/mem`:

```c
#define GCC_BASE 0x00100000
#define GCC_USB30_PRIM_MASTER_CLK 0xf00c

/* Initiate a connection via a pre-established socket fd */
rdevmem_session_t session = rdevmem_init_socket_fd(fd);

/* Connect to the listening rdevmem server on the target */
int error = rdevmem_hello(session);
if (error) {
    fprintf(stderr, "Failed to send hellow");
    return 1;
}

/* Get a handle to a region of memory on the target */
int handle = rdevmem_mmap(session, GCC_BASE, 0x1f0000);
if (handle < 0) {
    fprintf(stderr, "Failed to mmap memory\n");
    return 1;
}

uint32_t value;
error = rdevmem_readl(session, handle, GCC_USB30_PRIM_MASTER_CLK, &value);
if (error) {
    fprintf(stderr, "Failed to read");
    return 1;
}

printf("USB30_PRIM_MASTER_CLK: %010x\n", value);
```

## Building

To make cross compiling as simple as possible, rdevmem should be built as a
static binary, linked against musl. This can be done directly with the tools in
this repo.

```sh
# Set up cross compiler toolchain and libc. We disable CXX support, enable Linux
# headers, use all CPU cores, and enable pkg-config.
./mussel/mussel.sh aarch64 -x -p -l -k 

# Simple meson wrapper to select a cross compiler config and enable LTO
# Set up the build environment
./meson-cross -a aarch64 setup build 

# Now compile rdevmem
./meson-cross compile -C build
```

The resulting binary can be deployed to any aarch64 device with any libc and
provided that the kernel API is not radically different (e.g. memfd and
`/dev/mem` are supported) it should just work.

## Not limited to Linux

The protocol is designed to be fairly minimal, although it could use some work.
It should be suitable to write a server implementation for bootloader like
U-Boot. This would then work with all the same debug tools for interacting with
clocks or other peripherals.
