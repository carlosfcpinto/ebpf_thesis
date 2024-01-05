# eBPF ls 

The purpose of this example is to have an eBPf application that mimics the behavior of the ls command, showing the contents of a directory from which a `syscall` to `chdir` is made.

### Running

Calling the command `make` compiles both the kernel side of the code, and the user side of it.  To then run the program all that is needed is to execute `sudo ./eBPF_ls`.
To see the program running all you need to do is to open another terminal window and change directories a few times.
This program assumes that the shell being used is `zsh`, and will only work that way. A simple change to `eBPF_ls.c`, switching `zsh` to `bash` would solve this.
