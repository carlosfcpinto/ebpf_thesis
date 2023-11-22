from bcc import BPF
from bcc.utils import printb

BPF_SOURCE_CODE = r"""
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
   bpf_trace_printk("Hello. Creating new program: %s\n", args->filename);
   return 0;
}
"""

bpf = BPF(text = BPF_SOURCE_CODE)

while True:
    try:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
        printb(b"%-6d %s" % (pid, msg))
    except ValueError:
        continue
    except KeyboardInterrupt:
        break
