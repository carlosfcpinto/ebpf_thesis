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

### Miscellaneous
- `bpf_trace_printk()` always writes to `sys/kernel/debug/tracing/trace_pipe`  
- `sudo` is a `syscall` in itself, we can block that, answwering the question of how does it behave in a system with root privileges  

### Thoughts
Formally verifying an eBPF program may seem simple since it accepts only limited instructions and we can add predicates as to what each function does. This shall be the main focus of the assignment during its last part, but the only reference found to this was in this [implementation in Coq.](https://www.sccs.swarthmore.edu/users/16/mmcconv1/pl-reflection.html) It is however for BPF code, beeing that eBPF code is a bit more complex than that, making use of more complex data structures(?). The BPF language is essentially composed of ```C
struct bpf_insn {
         u_int16_t       code;
         u_char          jt;
         u_char          jf;
         u_int32_t       k;
 };
```
This will be the main focus of the formal verification process of this thesis.
