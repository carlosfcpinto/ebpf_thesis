# eBPF ls 

The purpose of this example is to have an eBPf application that mimics the behavior of the ls command, showing the contents of a directory from which a `syscall` to `execve` is made.

### Running

Calling the command `make` compiles both the kernel side of the code, and the user side of it.  To then run the program all that is needed is to execute `sudo ./eBPF_ls`.
To see the program running all you need to do is to open another terminal window and execute some linux commands, such as `ps`, `ls`, etc.
