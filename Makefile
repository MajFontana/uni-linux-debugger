all: build run

build:
	@gcc -m32 -fPIE -o spo_debug main.c

run:
	@./spo_debug

clean:
	@if [ -f spo_debug ]; then rm spo_debug; fi