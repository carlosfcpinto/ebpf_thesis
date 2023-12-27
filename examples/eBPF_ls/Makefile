# TARGET = eBPF_ls
# ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
#
# BPF_OBJ = ${TARGET:=.bpf.o}
# USER_C = ${TARGET:=.c}
# USER_SKEL = ${TARGET:=.skel.h}
#
# all: $(TARGET) $(BPF_OBJ) find-map
# .PHONY: all 
#
# $(TARGET): $(USER_C) $(USER_SKEL) 
# 	gcc -Wall -o $(TARGET) $(USER_C) -L../libbpf/src -l:libbpf.a -lelf -lz
#
# %.bpf.o: %.bpf.c vmlinux.h
# 	clang \
# 	    -target bpf \
#         -D __TARGET_ARCH_$(ARCH) \
# 	    -Wall \
# 	    -O2 -g -o $@ -c $<
# 	llvm-strip -g $@
#
# $(USER_SKEL): $(BPF_OBJ)
# 	bpftool gen skeleton $< > $@
#
# vmlinux.h:
# 	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
#
# clean:
# 	- rm $(BPF_OBJ)
# 	- rm $(TARGET)
# 	- rm find-map
#
# find-map: find-map.c
# 	gcc -Wall -o find-map find-map.c -L../libbpf/src -l:libbpf.a -lelf -lz
INCLUDES := -I$(OUTPUT)
CFLAGS := -g -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
APPS = eBPF_ls

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install
# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) vmlinux.h | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info
# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@
# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@
	
# Build application binary
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ -lelf -lz -o $@

