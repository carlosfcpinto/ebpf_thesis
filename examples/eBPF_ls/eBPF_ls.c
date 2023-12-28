#include "eBPF_ls.h"
#include "eBPF_ls.skel.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level >= LIBBPF_DEBUG)
    return 0;

  return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
  struct data_t *m = data;

  printf("%-6d %-6d %-16s %-16s %s\n", m->pid, m->uid, m->command, m->path,
         m->message);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz) {
  printf("lost event\n");
}

int main() {
  struct eBPF_ls_bpf *skel;
  int err;
  struct perf_buffer *pb = NULL;

  libbpf_set_print(libbpf_print_fn);

  skel = eBPF_ls_bpf__open_and_load();
  if (!skel) {
    printf("Failed to open BPF object\n");
    return 1;
  }

  err = eBPF_ls_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    eBPF_ls_bpf__destroy(skel);
    return 1;
  }

  // handle_event, lost_event and NULL NULL need to be in a struct of type
  // perf_buffer_opts
  // struct perf_buffer_opts pb_aux = {handle_event, lost_event, NULL};
  // struct perf_buffer_opts *pb_opt = &pb_aux;
  pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event,
                        lost_event, NULL, NULL);
  if (!pb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    eBPF_ls_bpf__destroy(skel);
    return 1;
  }

  while (true) {
    err = perf_buffer__poll(pb, 100 /* timeout, ms */);
    // Ctrl-C gives -EINTR
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      printf("Error polling perf buffer: %d\n", err);
      break;
    }
  }

  perf_buffer__free(pb);
  eBPF_ls_bpf__destroy(skel);
  return -err;
}
