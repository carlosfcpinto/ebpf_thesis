# Preventing Data Exfiltration in Virtual machines

The proposed thesis focus on the preventing of data exfiltration using eBPF. This shall be subject to a process of formal verification.

## Objectives

The main objective of this thesis is the development of an eBPF application that prevents data exfiltration from a certain machine. This module will then go through a formal verification process, before deployment. 

The fact that we use eBPF is particularly useful, since the classical approach of static configurations, although they work when configured statically during the provisioning of the machine, they become brittle when deployed across a fleet of machines and in the face of changing policies.

This application will serve the purpose of restricting services and capabilities inside the kernel, based on a per user or service approach, effectively armoring/shielding the system from unwanted accesses, either to services or files.

## State of The Art

Currently, one tool that provides such application is Google's **Kernel Runtime Security Instrumentation**, (KRSI), which makes use of the **Linux Security Module**, (LSM), and **eBPF**, allowing for the implementation of LSM hooks in eBPF code.
On the topic of the formal verification of eBPF code, a note has been made on *notes.md*, pointing to a link of a tool developed in coq for the formal verification of BPF code, which closely resembles machine code formal verification. There's also a tool for the formal verification of **LLVM** code, which can be an option, being that the compilation of eBPF kernel code makes use of **clang** and the **LLVM** project. (Further research is needed being that the latter tool seems rather simplistic, and perhaps not exactly what is needed.)
The most realistic approach, being the hardest one aswell, would be the development of a tool that generates verification conditions from eBPF kernel code and can load it into the **Why3** framework, making use of **SMT solvers** to discharge said conditions.
Being that eBPF code has some restraints, going through a process of static analysis to guarantee certain properties of it, we can focus mainly on the formal verification of what the program is supposed to do. A BPF instruction is of type

    struct bpf_insn {
        u_int16_t       code;
        u_char          jt;
        u_char          jf;
        u_int32_t       k;  
    };

## Potential Problems

There is the risk of potential tampering with the eBPF module written. That is, if there were to be another eBPF module written that would attach to the same events as the one preventing data exfiltration, there is the potential of it preventing the first one from working as intended. We should then make sure that the module is always active and can not be bypassed.
Some potential fixes for this are:

- Load Time Security -> Ensuring that the program is loaded securely, making sure only authorized users or services could alter it. (This approach seems too simplistic.)
- Using *seccomp* filters -> Restricting the system calls that can be made by the processes running the eBPF program.
- eBPF Map Access Controls -> Ensure that only authorized processes and users can read from or write to these maps.
- Kernel Module Signing -> We could potentially sign the module to prevent unauthorized modifications. (This seems to be the most realistic and safest approach, but it implies the implementation of the eBPf program as a kernel module, if not there may be a way to sign the program with a private key, and making the kernel only accept the loading of it if the public keys match!)
- User and Group Permissions -> Another approach is to restrict the *bpf* system call to authorized users and services, preventing the writing of another eBPF module entirely

## Questions

Are the users supposed to have root acces? If so, they will have unchecked access to the kernel, if not then they will not be able to by pass the first eBPF program loaded, which would prevent some of the potential problems described above.

## Tasks

The following tasks must be done, in order to obtain the expected results:

1. Studying of the underlying concepts of eBPF and formal Verification of eBPF code.
2. State of the Art
3. Design and implementation of the eBPF application
4. Formal verification
5. Validation, testing and analysis of results
6. Writing of the report

The proposed timeline would look something like:
| Objective| Time Expected    |
|--------------- | --------------- |
| 1+2   | 1.5 months   |
| 3   | 2 months   |
| 4   | 3 months   |
| 5   | 2 months   |

This timeline will serve more as a guide than a hard limit on the time spent on each of these topics, being that the task 5 can be included in both the development of the eBPF application and the formal verification of said application, if needed.

The formal verification  of eBPF code will the most challenging task, and as such it is the largest sum of time allocated in the planned timeline, being that the approach is not yet well defined and might include the development of an additional tool, as stated above.

Overall, I think this is a realistic approach to this project and one that can be used as a guide for the expected time of the thesis itself.

## Expected results

- 1 eBPF application, formally verified
- 1 formal verification tool for eBPF code 
- 1 report
