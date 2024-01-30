#include "eBPF_ls.h"
#include "vmlinux.h"
#include <asm-generic/errno-base.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char message[12] = "Hello World";

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} output SEC(".maps");

// map uid to a struct with filenames that user cannot change
struct user_msg_t {
  char message[12];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, u32);
  __type(value, struct msg_t);
} my_config SEC(".maps");

// path_chmod or file_permission
SEC("lsm/path_chmod")
int BPF_PROG(path_chmod, const struct path *path, umode_t mode) {
  struct data_t data = {};
  struct msg_t *p;
  u64 uid;

  data.pid = bpf_get_current_pid_tgid() >> 32;
  uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  data.uid = uid;

  bpf_printk("This user %d\n", uid);
  // ring buffer should be initialized in user side to contain the name of files
  // to be denied access to
  // directory is present in path -> dentry -> d_iname

  /* bpf_get_current_comm(&data.command, sizeof(data.command)); */
  /* bpf_probe_read_user_str(&data.path, sizeof(data.path),
   * path->dentry->d_iname); */

  // read config from map, see if user has restrictions
  p = bpf_map_lookup_elem(&my_config, &data.uid);
  if (p != 0) {
    bpf_printk("This user %d\n", data.uid);
    bpf_printk("Access denied to %s", path->dentry->d_iname);
    return -EPERM;
  } else {
    bpf_printk("This user %d\n", data.uid);
    bpf_printk("Chmod allowed to %s", path->dentry->d_iname);
    return 0;
  }

  /*   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data,
   * sizeof(data)); */
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// #include "eBPF_ls.h"
// #include "vmlinux.h"
// #include <bpf/bpf_core_read.h>
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <dirent.h>
// #include <string.h>
//
// // #define TARGET_DIR "/path/to/your/directory"
// //
// // struct {
// //   __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
// //   __uint(key_size, sizeof(u32));
// //   __uint(value_size, sizeof(u32));
// // } output SEC(".maps");
// //
// // SEC("kprobe/sys_execve")
// // int kprobe__sys_execve(struct pt_regs *ctx) {
// //   struct data_t data = {};
// //   /* struct filename *filename; */
// //   char buf[256];
// //   bpf_probe_read_str(buf, sizeof(buf), (void *)PT_REGS_PARM1(ctx));
// //
// //   /*   if (strncmp(buf, TARGET_DIR, sizeof(TARGET_DIR) - 1) == 0) { */
// //   // Log the executed file
// //   // bpf_trace_printk("Executed file in target directory: %s\n", buf);
// //   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data,
// //   sizeof(data));
// //
// //   // Log the files in the target directory
// //   // bpf_trace_printk("Files in target directory:\n");
// //
// //   /* struct file *file;
// //   struct dir_context ctx = {.actor = NULL};
// //
// //   file = kern_path_file(buf, LOOKUP_FOLLOW, 0);
// //   if (file) {
// //     iterate_dir(file->f_path.dentry, 0, &ctx);
// //     fput(file);
// //     }
// // */
// //
// //   return 0;
// // }
// //
// // char LICENSE[] SEC("license") = "Dual BSD/GPL";
//
// BPF_PERF_OUTPUT(events);
//
// SEC("kprobe/sys_execve")
// int kprobe__sys_execve(struct pt_regs *ctx) {
//   struct data_t data = {};
//   struct filename *filename;
//   struct path *path;
//   char buf[PATH_MAX];
//
//   bpf_probe_read_user(&filename, sizeof(filename), (void *)(ctx->di));
//   bpf_probe_read_user(&path, sizeof(path), &filename->f_path);
//
//   // Get the process ID
//   data.pid = bpf_get_current_pid_tgid() >> 32;
//
//   // Get the path of the executable
//   bpf_probe_read_user_str(buf, sizeof(buf), path->dentry->d_iname);
//   bpf_strncpy(data.filename, buf, sizeof(data.filename));
//
//   // Send the data to user space
//   events.perf_submit(ctx, &data, sizeof(data));
//
//   return 0;
// }
