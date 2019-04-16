from ubuntu:latest
copy hammer_controller.bin /
copy libc.so.6.binary /libc.so.6
copy ld-linux-x86-64.so.2.binary /ld-linux-x86-64.so.2

entrypoint ["/ld-linux-x86-64.so.2", "--library-path", "/", "/hammer_controller.bin", "himinbjörg_is_home", "loki_sucks_ass"]
