.PHONY: all docker_file

all: hammer_controller.bin docker_file

hammer_controller.bin: hammer_controller.c
	gcc -fno-stack-protector -no-pie -o hammer_controller.bin hammer_controller.c

docker_file: hammer_controller.bin
	docker build -t rex_tests:hammer_controller .