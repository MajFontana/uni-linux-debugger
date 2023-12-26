#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>



#include <wordexp.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/personality.h>
#include <signal.h>
#include <errno.h>






#define TRAP_INST 0xcc // int3
#define TRAP_MASK 0xff






void readInputWords(wordexp_t* words_ptr)
{
    // read line from stdin
    char* line = NULL;
    size_t size;
    getline(&line, &size, stdin);



    // split line into words
    char* end = strchr(line, '\n');
    *end = '\0';
    int flags = 0;

    if (words_ptr->we_wordv != NULL)
    {
        flags |= WRDE_REUSE;
    }

    wordexp(line, words_ptr, flags);



    free(line);
}





void* getTargetStartAddress(pid_t pid)
{
    // generate path
    char maps_path [64];
    sprintf(maps_path, "/proc/%d/maps", pid);



    // read beginning of file
    char data [64];
    int file = open(maps_path, O_RDONLY);
    read(file, data, 64);
    close(file);



    // end string at first '-'
    char* delim = memchr(data, '-', 64);
    *delim = '\0';
    void* start_addr = (void*) strtol(data, NULL, 16);
    return start_addr;
}






int runTarget(pid_t pid)
{
    // resume target and wait until it changes state again
    int status;
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &status, 0);
    return status;
}



int runTargetSingle(pid_t pid)
{
    // resume target for a single step and wait until it changes state again
    int status;
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    waitpid(pid, &status, 0);
    return status;
}






bool isTargetTrapped(int status)
{
    return WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP;
}






void debugLoop(pid_t pid)
{
    int status;
    void* breakpoint;
    unsigned long int orig_code;
    bool keep_breakpoint;



    // wait for target to get trapped once it's loaded
    int result = waitpid(pid, &status, 0);

    if (result == -1 || !isTargetTrapped(status))
    {
        fprintf(stderr, "Couldn't start debugging the target\n");
        exit(EXIT_FAILURE);
    }



    void* start_addr = getTargetStartAddress(pid);



    // command input loop - as long as the target is in an expected state
    wordexp_t words;
    words.we_wordv = NULL;
    bool quit = false;

    while (isTargetTrapped(status) && !quit)
    {
        // prompt and parse user input
        printf(">");
        fflush(stdout);
        readInputWords(&words);

        if (words.we_wordc < 1)
        {
            // user input was empty
            quit = true;
            continue;
        }

        char* cmd = words.we_wordv[0];
        char** args = words.we_wordv + 1;
        int arg_count = words.we_wordc - 1;



        // sets a one-time breakpoint
        if (strcmp(cmd, "b") == 0 && arg_count == 1)
        {
            unsigned long int offset = strtol(args[0], NULL, 16);
            void* addr = start_addr + offset;
            
            if (errno == 0 && addr > 0)
            {
                breakpoint = addr;
                keep_breakpoint = false;
            }

            else
            {
                printf("Invalid address");
            }
        }

        // sets a breakpoint
        else if (strcmp(cmd, "bs") == 0 && arg_count == 1)
        {
            unsigned long int offset = strtol(args[0], NULL, 16);
            void* addr = start_addr + offset;

            if (errno == 0 && addr > 0)
            {
                breakpoint = addr;
                keep_breakpoint = true;
            }

            else
            {
                printf("Invalid address");
            }
        }

        // clears the breakpoint
        else if (strcmp(cmd, "br") == 0 && arg_count == 0)
        {
            breakpoint = NULL;
        }

        // advances the target by a single instruction
        else if (strcmp(cmd, "s") == 0 && arg_count == 0)
        {
            status = runTargetSingle(pid);
        }

        // resumes the target until the next breakpoint or exit
        else if (strcmp(cmd, "c") == 0 && arg_count == 0)
        {
            // single step into the target first, in case the current
            // instruction will get overriden by the breakpoint trap
            status = runTargetSingle(pid);

            if (!isTargetTrapped(status))
            {
                // target is in an unexpected state
                quit = true;
                continue;
            }



            if (breakpoint != NULL)
            {
                // remember the original code, and replace it with the trap instruction
                orig_code = ptrace(PTRACE_PEEKTEXT, pid, breakpoint, NULL);
                unsigned long int mod_code = (orig_code & ~TRAP_MASK) | TRAP_INST;
                ptrace(PTRACE_POKETEXT, pid, breakpoint, mod_code);
            }



            status = runTarget(pid);

            if (!isTargetTrapped(status))
            {
                // target is in an unexpected state
                quit = true;
                continue;
            }



            if (breakpoint != NULL)
            {
                // restore the code to the original
                ptrace(PTRACE_POKETEXT, pid, breakpoint, orig_code);
                
                if (!keep_breakpoint)
                {
                    breakpoint = NULL;
                }



                // decrement the instruction pointer, so that next time
                // the original instruction can be executed
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                regs.eip--;
                ptrace(PTRACE_SETREGS, pid, NULL, &regs);
            }
        }

        // prints the content of a word of memory
        else if (strcmp(cmd, "p") == 0 && arg_count == 1)
        {
            unsigned long int offset = strtol(args[0], NULL, 16);
            void* addr = start_addr + offset;

            if (errno == 0 && addr > 0)
            {
                unsigned long int data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
                printf("0x%08lx\n", data);
            }

            else
            {
                printf("Invalid address");
            }
        }

        // no valid command signature was matched
        else
        {
            printf("Unknown command. Available commands:\n"
            "   b <address>    set one-time breakpoint\n"
            "   bs <address>   set breakpoint\n"
            "   br             clear breakpoint\n"
            "   s              single step\n"
            "   c              resume program\n"
            "   p <address>    show memory content\n");
        }
    }



    // we're finished debugging, clean up and display the reason



    wordfree(&words);



    if (WIFSTOPPED(status))
    {
        kill(pid, SIGKILL);

        if(WSTOPSIG(status) != SIGTRAP)
        {
            printf("Target stopped by signal number %d. Terminating ...\n", WSTOPSIG(status));
        }
    }

    else if (WIFEXITED(status))
    {
        printf("Target exited\n");
    }

    else if (WIFSIGNALED(status))
    {
        printf("Target terminated by signal number %d\n", WTERMSIG(status));
    }
}






void loadTarget(char* path, unsigned int arg_count, char** args)
{
    // prepare null terminated argument and evnironment arrays for target program
    char* exec_args [arg_count + 1];

    for (int i = 0; i < arg_count; i++)
    {
        exec_args[i] = args[i];
    }

    exec_args[arg_count] = NULL;
    char* exec_env [] = {NULL};


    // make current process traced
    ptrace(PTRACE_TRACEME, NULL, NULL, NULL);



    // rewrite memory with target's process image and execute it
    personality(ADDR_NO_RANDOMIZE);
    int result = execve(path, exec_args, exec_env);

    if (result == -1)
    {
        fprintf(stderr, "Couldn't load %s\n", path);
        exit(EXIT_FAILURE);
    }
}






int main(int argc, char* argv [])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s target_path [target_args ...]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char* target_path = argv[1];



    pid_t child_pid = fork();

    if (child_pid == 0)
    {
        // we're the child process, load the target program
        loadTarget(target_path, argc - 2, argv + 2);
    }

    else if (child_pid > 0)
    {
        // we're the parent process, start debugging the child process
        debugLoop(child_pid);
    }



    return 0;
}