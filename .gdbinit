set debuginfod enabled on
set confirm off
python gdb.events.exited.connect(lambda x : gdb.execute("quit"))

r
bt full
q

