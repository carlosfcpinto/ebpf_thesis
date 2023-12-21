#include "eBPF_ls.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <dirent.h>
#include <string.h>

#define TARGET_DIR "/path/to/your/directory"

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} output SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe__sys_execve(struct pt_regs *ctx) {
  struct data_t data = {};
  /* struct filename *filename; */
  char buf[256];
  bpf_probe_read_str(buf, sizeof(buf), (void *)PT_REGS_PARM1(ctx));

  if (strncmp(buf, TARGET_DIR, sizeof(TARGET_DIR) - 1) == 0) {
    // Log the executed file
    // bpf_trace_printk("Executed file in target directory: %s\n", buf);
    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));

    // Log the files in the target directory
    // bpf_trace_printk("Files in target directory:\n");

    /* struct file *file;
    struct dir_context ctx = {.actor = NULL};

    file = kern_path_file(buf, LOOKUP_FOLLOW, 0);
    if (file) {
      iterate_dir(file->f_path.dentry, 0, &ctx);
      fput(file);
      }
*/
  }

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
