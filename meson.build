project('rdevmem', 'c')

deps = [
]

src = [
    'rdevmem.c',
    'librdevmem.c',
]

executable('rdevmem', src,
    dependencies: deps,
    link_args: ['-static', '-static-libgcc'],
    install: true)

