# Linux Debugger (school project)

A C program that lets you debug binary programs by setting a breakpoint, reading memory locations and single-stepping through instructions.


## Usage

To compile the program run

```bash
make build
```

Then start debugging a program by running

```
debug target_path [target_args ...]
```

Available commands:

| Command | Description |
|-|-|
| b \<address> | set one-time breakpoint |
| bs \<address> | set breakpoint |
| br | clear breakpoint |
| s | single step |
| c | resume program |
| p \<address> | show memory content |


## Note

The debugger is a simple proof of concept. It will not properly handle programs that rely on signals or spawn new processes.