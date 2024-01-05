all: build run

build:
	@gcc -m32 -fPIE -o debug main.c

run:
	@./debug

clean:
	@if [ -f debug ]; then rm debug; fi