# eBPF

Runs custom code in the kernel.
Normal apps are written in userspace, using system calls to communicate with the kernel, triggering an event, which can be captured with an eBPF program. Examples of events: kprobes, uprobes, tracepoints, network packets, linux security module, perf events, etc.

## eBPF Maps

Maps are a generic data structure, as is known they allow for sharing of data between eBPF kernel programs, and also between kernel and user-space applications.
Map types have attributes: 

- type
- max number of elements
- key size (in bytes)
- value size (in bytes)
  Typical uses include:
- User space writing configuration information to be retrieved by an eBPF program
- An eBPF program storing state, for later retrieval by another eBPF program
- An eBPF program writing results or metrics into a map, for retrieval by the user space app that will present results

## eBPF Code

Userspace and kernel eBPF programs.
Userspace application code makes the connection between the two.
Kernel eBPF programs are written in a restricted C tht is compiled into eBPF programs. We have access to helper functions.

## eBPF Programs

eBPF programs are event-drive, running when a certain hook point is passed. Pre-defined hooks exist such as sys calls, function entry/exit, kernel tracepoints, network events, etc.
If a predefined hook does not exist, we can create a kernel probe (kprobe) or user probe (uprobe) to attach eBPF programs almost anywhere in kernel or user applications.

### Attach custom code to event

```C
x = bpf(BPF_PROG_LOAD, ...);
y = perf_event_open(...);
ioctl(y, PERF_EVENT_IOC_SET_BPF, x);
```

## Types of Maps

### Hash Tables

Self-explanatory. Key-value pairs stored in a hash table.

### Ring buffers

Ring buffers can be classified as a piece of memory logically organized in a ring, with separate "write" and "read" pointers. Data of arbitrary length gets written to wherever the write pointer is, with the length information included in a header for the data. Thee write pointer moves to after the end of that data, ready for the next write operation.
In a read operation, data gets read from wherever the read pointer is, using the header to determine how much data to read. The read pointer moves along in the same direction as the write pointer so that it points to the next available piece of data.
If the read pointer catches up with the write pointer, it simply means there's no data to read. If a write operation would make the pointer overtake the read pointer, the data doesn't get written and a $ drop counter $ gets incremented. Read operations include the drop counter to indicate whether data has been lost since the last successful read.
If read and write operations happened at precisely the same rate with no variability, and they always contained the same amount of data, you could at least in theory get away with a ring buffer just big enough to accommodate that data size. In most applications there will be some variation in the time between reads, writes, or both, so the buffer size needs to be tuned to account for this.

## Function calls

### Tail Calls

Tail calls can call and execute another eBPF program and replace the execution context, similar to how the $execve()$ system call operates for regular processes. Execution doesn't return to the caller after a tail call completes.
Tail calls are made using:
`long bpf_tail_call(void *ctx, struct bpf_map *prog_array_map, u32 index)`
the three arguments to this functino have the following meanings:

- ctx allows passing the context from caller to callee
- prog_array_map is an eBPF map of type BPF_MAP_TYPE_PROG_ARRAY, holding a set of file descriptors that identify eBPF programs
- index indicates which of that set of eBPF programs should be invoked

## eBPF Registers

eBPF makes use of 10 general-purpose registers, numbered from 0 to 9. Register 10 is used as a stack frame pointer, (read only). These registers are implemented in software, **BPF_REG_0** to **BPF_REG_9** in the Linux kernel's source code.

The context argument to an eBPF program is loaded into register 1 before execution begins. The return value from the function is stored in register 0.

Before calling a function from eBPF code, the arguments are placed in registers 1 through 5, as needed.

## eBPF Instructions

`struct bpf_insn {
__u8 code; /* opcode */
__u8 dst_reg:4; /* dest register */
__u8 src_reg:4; /* source register */
__s16 off; /* signed offset */
__s32 imm; /* signed immediate constant */
};`

Each instruction has an opcode, defining what operation the instruction is set to perform.

Different operations might involve up to two registers.

Depending on the operatino, there might be an offset value and/or an immediate intenger value.

This structure is 64 bits long, but it may make use of *wide instruction encoding* that is 16 bytes long in total if, for example, there is need to set a register to a 64-bit value. eBPF bytecode is represented by a series of these instructions.

Most opcodes are one of the following: 

- Loading a value into a register

- Storing a value from a register into memory

- Performing arithmetic operations

- Jumping to a different instruction if a particular condition is satisfied

## bpf() System Call

NOTE: eBPF code running in the kernel does not use syscalls to access maps. The syscall interface is only used by user space applications.

The bpf() syscall is used to perform a command on an extended BPF map or program, with signature: `int bpf(int cmd, union bpf_attr *attr, unsigned int size)` 

The first argument, *cmd*, specifies which command to perform.

The *attr* argument holds whatever data is needed to specify the parmeters for the command.

The *size* indicates how many bytes of data there are in *attr*.

Programs and maps are created using the **BPF_PROG_LOAD** and **BPF_MAP_CREATE** commands. The kernel keeps track of the number of references to eBPF programs and maps, releasing them when the reference count drops to zero.



## CO-RE

CO-RE means compile once, run everywhere, which makes the eBPF programs portable across different kernel versions, making use of BTF, (BPF Type Format).

### CO-RE Overview

- BTF: BTF is a format for expressing the layout of data structures and function signatures. Used to determine any differences between the structures used at compilation time and at runtime.

- Kernel Headers: The Linux kernel source code includes header files that describe the data structures it uses. We can include individual header files, or use *bpftool* to generate a header file called *vmlinux.h*, containing all the data structure information about a kernel that a BPF program might need. **bpftool btf dump file /sys/kenerl/btf/vmlinux format c > vmlinux.h**

- Compiler support: The *clang* compiler was enhanced so that when it compiles eBPF programs with the -g flag, it includes CO-RE relocations, derived from the BTF information describing the kernel data structures.

- Library support for data structure relocations: When loading an eBPF program into the kernel, the CO-RE approach requires the bytecode to be adjusted to compensate for any differences between the data structures present when it was compiled, and what's on the target machine.

- BPF Skeleton (Optional): A skeleton can be auto-generated from a compiled BPF object file, containing functions that user space code can call to manage the lifecycle of BPF programs.



## Using System Calls for Security Events

**Seccomp** - used to limit the set of syscalls a process can use to a very small subset: *read(), write(), _exit(), sigreturn()_*. The intention was to allow users to run untrusted code without any possibility of that code doing malicious things. However, it is too restrictive, and so *seccomp-bpf* is used, which uses BPF code to filter the syscalls that are and aren't allowed. In seccomp-bpf a set of BPF instructions are loaded that act as a filter. Each time a syscall is called, the filter is triggered. The filter code has acces to the arguments that are passed to the syscall so that it can make decisions based on both the syscall itself and the arguments tha have been passed to it. (We could use this to prevent certain directories being shown in the **ls** command, which uses a sycall aswell). Seccomp-bpf does oe of the following:

- allows the syscall to go ahead

- return an error code to the user space application

- kill the thread

- notify a user space application (as of kernel 5.0)

However, some of the arguments of syscalls are pointers, and seccomp-bpf cannot dereference these pointers. This limits seccomp-bpf as it can only use value arguments when making decisions.



The best-known tool that uses syscall-tracking security is the CNCF project **Falco**, which provides security alerts. It is, by default, installed as a kernel module, but there is also an eBPF version. Users can define rules to determine what events are security relevant, and Falco can generate alerts in a variety of formats when events happen that don't match the policies defined in these rules. It has, however, a TIme Of Check to Time of Use issue. When an eBPF program is triggered at the entry point to a system call, it can access the arguments that user space has passed to that system call. If those arguments are pointers, the kernel will need to copy the pointed-to data into its own data structures before acting on that data, as such, there is a window of opportunity for an attacker to modify this data, after it has been inspected by the eBPF program but before the kernel copies it, making the data that is being acted on not the same as what was captured by the eBPF program. The **Sysmon for Linux tool** addresses the TOCTOU window by attaching to both the entry and exit points for syscalls. Once the call has completed, it looks at the kernel's data structures to get an accurate view, but it cannot prevent an action from taking place, since the syscall has already completed by the time a check is made. To efectively solve this, the eBPF program should be attached to an event that occurs after the parameters have been copied into kernel memory. There is no easy way to do this, but there is however a well-defined interface where eBPF programs can be safely attached: the Linux Security Module API.



### BPF LSM

The LSM interface provides a set of hooks that each occur just before the kernel is about to act on a kernel data structure. The function called by a hook can make a decision about wheter to allow the action to go ahead. (Interesting example on **chmod** syscall on page 179 of Learning eBPF).



## Network Security

eBPF programs that attach to points in the network stack can drop packets if they are determined to be out of policy.

Network security tools are often used in a preventative mode, dropping packets rather than just auditing malicious activity. This is because it's incredibly easy to mount network-related attacks.

## Miscellaneous

- `bpf_trace_printk()` always writes to `sys/kernel/debug/tracing/trace_pipe`  
- `sudo` is a `syscall` in itself, we can block that, answwering the question of how does it behave in a system with root privileges

### Thoughts

Formally verifying an eBPF program may seem simple since it accepts only limited instructions and we can add predicates as to what each function does. This shall be the main focus of the assignment during its last part, but the only reference found to this was in this [implementation in Coq.](https://www.sccs.swarthmore.edu/users/16/mmcconv1/pl-reflection.html) It is however for BPF code, being that eBPF code is a bit more complex than that, making use of more complex data structures(?). The BPF language is essentially composed of ```C
struct bpf_insn {
         u_int16_t       code;
         u_char          jt;
         u_char          jf;
         u_int32_t       k;
 };```

This will be the main focus of the formal verification process of this thesis.
