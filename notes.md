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

## Compiling an eBPF object file

`hello.bpf.o: %.o %.c`

`    clang \`

`        -target bpf \`

`        -I /usr/include/$(shell uname -m)-linux-gnu \`

`        -g \`

`        -02 -c $< -o \$@`

This will generate an object file called hello.bpf.o from the source code in hello.bpf.c. The -g flag will include debug information

## Compiling an eBPF object file for CO-RE

`hello.bpf.o: %.o %.c`

`    clang \`

`        -target bpf \`

`        -D __TARGET_ARCH_$(ARCH) \`

`        -I /usr/include/$(shell uname -m)-linux-gnu \`

`        -Wall \`

`        -02 -g \`

`        -c $< -o \$@`

`    llvm-strip -g $@`

## Loading the Program into the Kernel

We can use *bpftool* to load a program:

    - `bpftool prog load hello.bpf.o /sys/fs/bpf/hello`

This will load the eBPF program, "pinning" it to the location */sys/fs/bpf/hello*. No output is to be expected, which indicates success.

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

## BPF Skeletons

We can use *bpftool* to aut-generate skeleton code from existing eBPF objects in ELF file format, as such:

    - `bpftool gen skeleton hello-buffer-config.bpf.o > hello.buffer-config.skel.h`

This skeleton header will contain structure definitions for the eBPF programs and maps, as well as several functions. These functions manage the lifecycle of the eBPF programs and maps.

We can then call these functions, for example for opening and loading a program into the kernel, initializing a counter with a value of 10, as such:

``skel = hello_buffer_config_bpf__open();
if (!skel) {
    // Error ...
}
skel->data->c = 10;
err = hello_buffer_config_bpf__load(skel);``

We can also attach to an event, using: `err = hello_buffer_config_bpf__attach(skel);`

The *libbpf* library automatically takes the attachment point from the SEC() definition for this program. If no attachment is fully defined, there are other functions, such as `bpf_program__atach_kprobe` to attach different program types.

## eBPF Verifier

Verification involves checking every possible execution path through the program and ensuring that every instruction is safe. The verifier also updates some parts of the bytecode to ready it for execution.

The verifier analyzes the program, evaluating all possible expressions, rather than actually executing them. It keeps track of the state of each register in a structure called *bpf_reg_state*. Each time the verifier comes to a branch, where a decision is made, it pushes a copy of the current state of all the registers onto a stack and explores one of the possible paths. It keeps on doing this until it reaches the return at the end of the program, at which point it pops a branch off the stack to evaluate next. If it finds an instruction that could result in an invalid operation, it fails verification.

Verifying every single possibility is computationally unwise, therefore the verifier utilizes *pruning* to avoid reevaluating paths that are essentially equivalent.

When the verification  of a program fails, the verifier will generate a log.

It is also able to generate a control flow graph of the program in DOT format. Using the following commands, this DOT file is generated and then converted to a PNG file>

- `bpftool prog dump xlated name kprobe_exec visual > out.dot`

- `dot -Tpng out.dot > out.png`

It is necessary to check a pointer before dereferencing it, as such:

```c
if (p!=0){ //<- this checks if the pointer is null
    char a = p->message[0];
    bpf_printk("%d", a);
}
```

## eBPF Program and Attachment Types

Program context arguments: all eBPF programs take a context argument that is a pointer, but the structure it points to depends on the type of event that triggered it.

### Helper functions and Return Codes

The verifier will check if all helper functions used by a program are compatible with its program type. The program type in eBPF determines the meaning of the return code, guiding the kernel on how to handle the packet, in the case of XDP for example.

The availability of helper functions for each program type in a specific
 kernel version can be obtained using the "bpftool feature" command, 
providing a list of supported program types, map types, and helper 
functions. Helper functions are considered part of the Linux kernel's 
stable external interface (UAPI), aiming for stability despite ongoing 
BPF subsystem development.

### Kfuncs

Kfuncs in eBPF allow the registration of internal kernel functions with the BPF subsystem, permitting their invocation from eBPF programs after verification. Unlike helper functions, discussed above, kfuncs do not guarantee compativility across kernel versions.

There exists a registration for each eBPF program type allowed to call a
 specific kfunc. There is a set of "core" BPF kfuncs, including
 functions for obtaining and releasing kernel references to tasks and 
cgroups.

### Kprobes and Kretprobes

Kprobe programs can be attached to almost anywhere in the kernel. They are commonly attached using kprobes to the entry to a function and kretprobes to the exit of a function, but there is the possibility of attaching kprobes to an instruction that is some specified offset after the entry to the function.

### Fentry/Fexit

Fentry/fexit is now the preferred method for tracing the entry to or exit from a kernel function. The same code can be written inside a kprobe or fentry type program. In contrast to kretprobes, the fexit hook provides access to the input parmeters of the function.

### Tracepoints

Tracepoints are marked locations in the kernel code. They're not exclusive to eBPF and have long been used to generate kernel trace output. Unlike kprobes, tracepoints are stable between kernel releases.

With BPF support, there will be a structure defined in *vmlinux.h* that matches the context structure passed to a tracepoint eBPF program, effectively rendering the writing of structures for context parameters obsolete. The section definition should be **SEC("tp_btf/tracepoint name")** where the tracepoint name is one of the available events listed in */sys/kernel/tracing/available_events*.

### User Space Attachments

eBPF programs can also attach to events within user space code, utilizing *uprobes* and *uretprobes* for entry ad exit of user space functions, and user statically defined tracepoints (USDTs) for specified tracepoints in 
application code or user space libraries. These user space probes use 
the BPF_PROG_TYPE_KPROBE program type.

There are considerations and challenges when instrumenting user space code:

- The path to shared libraries is architecture-specific, requiring corresponding definitions.
- It's challenging to predict the installed user space libraries and applications on a machine.
- Standalone binaries may not trigger probes attached within shared libraries.
- Containers have their own filesystem and dependencies, making the path to shared libraries different from the host machine.
- eBPF programs may need to be aware of the language in which an application was written, considering variations in argument passing mechanisms.

Despite these challenges, several useful tools leverage eBPF to 
instrument user space applications. Examples include tracing decrypted 
versions of encrypted information in the SSL library and continuous 
profiling of applications using tools like Parca.

### LSM

**BPF_PROG_TYPE_LSM** programs, which are attached to the Linux Security 
Module (LSM) API, providing a stable interface in the kernel initially 
designed for kernel modules to enforce security policies.

**BPF_PROG_TYPE_LSM** programs are attached using 
`bpf(BPF_RAW_TRACEPOINT_OPEN)` and are treated similarly to tracing 
programs. An interesting aspect is that the return value of 
**BPF_PROG_TYPE_LSM** programs influences the kernel's behavior. A nonzero 
return code indicates a failed security check, preventing the kernel 
from proceeding with the requested operation, which contrasts with 
perf-related program types where the return code is ignored.

### Networking

Notably, these program types necessitate specific capabilities, 
requiring either **CAP_NET_ADMIN** and **CAP_BPF** or **CAP_SYS_ADMIN** capabilities
 to be granted.

The context provided to these programs is the network message under 
consideration, although the structure of this context depends on the 
data available at the relevant point in the network stack. At the bottom
 of the stack, data is represented as Layer 2 network packets—a sequence
 of bytes prepared or in the process of being transmitted over the 
network. On the other hand, at the top of the stack where applications 
interact, sockets are employed, and the kernel generates socket buffers 
to manage data transmission to and from these sockets.

One big difference between the networking program types and the tracing-related
types you saw earlier in this chapter is that they are generally intended to allow for the
customization of networking behaviors. That involves two main characteristics:

1. Using a return code from the eBPF program to tell the kernel what to do with a
   network packet—which could involve processing it as usual, dropping it, or redi‐
   recting it to a different destination
2. Allowing the eBPF program to modify network packets, socket configuration
   parameters, and so on

### Sockets

In the upper layers of the network stack, specific eBPF program types are dedicated to socket and socket-related operations:

1. **BPF_PROG_TYPE_SOCKET_FILTER:**
   
   - Primarily used for filtering a copy of socket data.
   - Not for filtering data directly sent to or from an application.
   - Useful for sending filtered data to observability tools like tcpdump.

2. **BPF_PROG_TYPE_SOCK_OPS:**
   
   - Applied to sockets specific to Layer 4 (TCP) connections.
   - Allows interception of various socket operations and actions.
   - Provides the ability to set parameters like TCP timeout values for a socket.
   - Sockets are limited to connection endpoints and are not present on intermediate devices.

3. **BPF_PROG_TYPE_SK_SKB:**
   
   - Utilized in conjunction with a special map type holding socket references.
   - Enables sockmap operations, facilitating traffic redirection to different destinations at the socket layer.

These program types offer capabilities ranging from filtering socket data for observability to controlling parameters and actions on sockets within Layer 4 connections.

### Traffic Control

Further down the network stack is the TC (traffic control) subsystem in 
the Linux kernel, which is complex and crucial for providing deep 
flexibility and configuration over network packet handling. eBPF 
programs can be attached to the TC subsystem, allowing custom filters 
and classifiers for both ingress and egress traffic. This is a 
fundamental component of projects like Cilium, and examples will be 
covered in the next chapter. Quentin Monnet's blog provides immediate 
examples for those interested. The configuration of these eBPF programs 
can be done programmatically or using the tc command.

### XDP

They attach to specific interfaces, allowing different programs for 
different interfaces. XDP programs can be managed using the `ip` command, and an example command to load and attach a program to eth0 is provided. The `ip link show` command displays information about the attached XDP program. To remove the XDP program, the `ip link set dev eth0 xdp off` command can be used.

### BPF Attachment Types

The attachment type in eBPF programs provides fine-grained control over where a program can be attached in the system. While some program types implicitly define their attachment type based on the hook they attach to, others require explicit specification. The attachment type influences the validity of helper functions and restricts access to certain context information.

In cases where an attachment type must be specified, the kernel function `bpf_prog_load_check_attach` checks its validity for specific program types. An example is provided for the CGROUP_SOCK program type, which can be attached at various points in the network stack.

To determine valid attachment types for programs, one can refer to the libbpf documentation, which also includes recognized section names for each program and attachment type. Understanding and correctly specifying attachment types are crucial when working with eBPF programs.

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

## Signed eBPF programs

Ongoing topic, perharps important to prevent third party eBPF programs from being loaded in the first place, as well as making sure that the program we intend to run is the correct one and has not been tampered with

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
