//! Pure heuristic classifiers for Linux forensic artifacts.
//!
//! This module consolidates all `classify_*` functions from the individual
//! walker modules into one discoverable, collectively-testable location.
//!
//! Each function is a pure heuristic: it takes only primitive values and
//! returns `bool` or a tuple — no `ObjectReader` dependency.
//!
//! The original walker modules re-export every symbol from here so all
//! existing call sites continue to compile unchanged.

// ---------------------------------------------------------------------------
// BPF program classification
// ---------------------------------------------------------------------------

/// Classify whether a BPF program type/name combination is suspicious.
///
/// Returns `true` for kprobe, lsm, raw_tracepoint_writable programs, and
/// unnamed tracing/raw_tracepoint programs.
pub fn classify_bpf_program(prog_type: &str, name: &str) -> bool {
    todo!("classify_bpf_program({prog_type:?}, {name:?})")
}

// ---------------------------------------------------------------------------
// Capabilities classification
// ---------------------------------------------------------------------------

/// Classify whether a non-root process holds suspicious Linux capabilities.
///
/// Returns `(is_suspicious, suspicious_cap_names)`. Root (uid == 0) is never
/// flagged.
pub fn classify_capabilities(effective: u64, uid: u32) -> (bool, Vec<String>) {
    todo!("classify_capabilities({effective}, {uid})")
}

// ---------------------------------------------------------------------------
// Cgroup classification
// ---------------------------------------------------------------------------

/// Classify whether a cgroup path indicates a container runtime.
///
/// Returns `(in_container, container_id)`. Recognises Docker, LXC, Kubernetes
/// and containerd path prefixes.
pub fn classify_cgroup(path: &str) -> (bool, String) {
    todo!("classify_cgroup({path:?})")
}

// ---------------------------------------------------------------------------
// AF-info hook classification
// ---------------------------------------------------------------------------

/// Classify whether a network protocol handler function pointer has been hooked.
///
/// Returns `true` when the address is non-zero and outside the kernel text range
/// `[kernel_start, kernel_end]`.
pub fn classify_afinfo_hook(hook_addr: u64, kernel_start: u64, kernel_end: u64) -> bool {
    todo!("classify_afinfo_hook({hook_addr}, {kernel_start}, {kernel_end})")
}

// ---------------------------------------------------------------------------
// Shared credentials classification
// ---------------------------------------------------------------------------

/// Classify whether shared `struct cred` pointers indicate credential theft.
///
/// Returns `true` when a non-kernel-thread shares credentials with init (PID 1)
/// or when unrelated processes share credentials.
pub fn classify_shared_creds(pid: u32, shared_with: &[u32], uid: u32) -> bool {
    todo!("classify_shared_creds({pid}, {shared_with:?}, {uid})")
}

// ---------------------------------------------------------------------------
// IDT entry classification
// ---------------------------------------------------------------------------

/// Classify whether an IDT handler address has been hooked.
///
/// Returns `true` when the address is non-zero and outside `[kernel_start, kernel_end]`.
pub fn classify_idt_entry(handler_addr: u64, kernel_start: u64, kernel_end: u64) -> bool {
    todo!("classify_idt_entry({handler_addr}, {kernel_start}, {kernel_end})")
}

// ---------------------------------------------------------------------------
// Container escape classification
// ---------------------------------------------------------------------------

/// Classify whether a process indicator suggests a container escape attempt.
///
/// Returns `false` for kernel threads regardless of indicator.
pub fn classify_container_escape(comm: &str, indicator: &str) -> bool {
    todo!("classify_container_escape({comm:?}, {indicator:?})")
}

// ---------------------------------------------------------------------------
// Deleted executable classification
// ---------------------------------------------------------------------------

/// Classify whether a process running from a deleted executable is suspicious.
///
/// Returns `false` for kernel threads, package manager processes, and processes
/// with empty paths/names.
pub fn classify_deleted_exe(exe_path: &str, comm: &str) -> bool {
    todo!("classify_deleted_exe({exe_path:?}, {comm:?})")
}

// ---------------------------------------------------------------------------
// Hidden dentry classification
// ---------------------------------------------------------------------------

/// Classify whether a dentry is hidden or suspicious.
///
/// Returns `true` when `nlink == 0` (unlinked file still mapped) or when the
/// filename has a suspicious extension despite being linked.
pub fn classify_hidden_dentry(nlink: u32, filename: &str) -> bool {
    todo!("classify_hidden_dentry({nlink}, {filename:?})")
}

// ---------------------------------------------------------------------------
// eBPF map classification
// ---------------------------------------------------------------------------

/// Classify whether an eBPF map is suspicious.
///
/// Flags high-risk map types (perf_event_array=3, ringbuf=26) and maps whose
/// names match known rootkit patterns.
pub fn classify_ebpf_map(map_type: u32, name: &str, value_size: u32) -> bool {
    todo!("classify_ebpf_map({map_type}, {name:?}, {value_size})")
}

// ---------------------------------------------------------------------------
// Ftrace hook classification
// ---------------------------------------------------------------------------

/// Classify whether an ftrace function pointer is outside the kernel text range.
///
/// Returns `true` when `func < stext || func >= etext`.
pub fn classify_ftrace_hook(func: u64, stext: u64, etext: u64) -> bool {
    todo!("classify_ftrace_hook({func}, {stext}, {etext})")
}

// ---------------------------------------------------------------------------
// Futex classification
// ---------------------------------------------------------------------------

/// Classify whether a futex entry is suspicious.
///
/// Returns `true` for excessive waiter counts (> 1000) or kernel-space keys
/// owned by a userspace process.
pub fn classify_futex(key_address: u64, owner_pid: u32, waiter_count: u32) -> bool {
    todo!("classify_futex({key_address}, {owner_pid}, {waiter_count})")
}

// ---------------------------------------------------------------------------
// io_uring classification
// ---------------------------------------------------------------------------

/// Classify whether an io_uring submission is suspicious.
///
/// Returns `false` when seccomp is disabled; returns `true` when seccomp is
/// active and the opcode list contains a sensitive syscall.
pub fn classify_io_uring(opcodes: &[u8], seccomp_mode: u32) -> bool {
    todo!("classify_io_uring({opcodes:?}, {seccomp_mode})")
}

// ---------------------------------------------------------------------------
// I/O memory region classification
// ---------------------------------------------------------------------------

/// Classify whether an `/proc/iomem` region entry is suspicious.
///
/// Flags empty names on large regions, non-ASCII names, and regions that
/// overlap the kernel text range without the expected name.
pub fn classify_iomem(name: &str, start: u64, end: u64) -> bool {
    todo!("classify_iomem({name:?}, {start}, {end})")
}

// ---------------------------------------------------------------------------
// Kernel timer classification
// ---------------------------------------------------------------------------

/// Classify whether a kernel timer callback is outside the kernel text range.
///
/// Returns `false` for null pointers; `true` when the callback is outside
/// `[kernel_start, kernel_end]`.
pub fn classify_kernel_timer(function: u64, kernel_start: u64, kernel_end: u64) -> bool {
    todo!("classify_kernel_timer({function}, {kernel_start}, {kernel_end})")
}

// ---------------------------------------------------------------------------
// Keyboard notifier classification
// ---------------------------------------------------------------------------

/// Classify whether a keyboard notifier callback is outside the kernel text range.
///
/// Returns `true` when `notifier_call < stext || notifier_call >= etext`.
pub fn classify_notifier(notifier_call: u64, stext: u64, etext: u64) -> bool {
    todo!("classify_notifier({notifier_call}, {stext}, {etext})")
}

// ---------------------------------------------------------------------------
// Kernel message classification
// ---------------------------------------------------------------------------

/// Classify whether a kernel log message matches known suspicious patterns.
pub fn classify_kmsg(text: &str) -> bool {
    todo!("classify_kmsg({text:?})")
}

// ---------------------------------------------------------------------------
// Kernel thread classification
// ---------------------------------------------------------------------------

/// Classify whether a kernel thread entry looks suspicious.
///
/// Returns `(is_suspicious, reason)`. Flags unnamed threads, threads with
/// userspace start-function addresses, and hex-pattern names.
pub fn classify_kthread(name: &str, start_fn_addr: u64) -> (bool, Option<String>) {
    todo!("classify_kthread({name:?}, {start_fn_addr})")
}

// ---------------------------------------------------------------------------
// LD_PRELOAD classification
// ---------------------------------------------------------------------------

/// Classify whether an `LD_PRELOAD` value references a suspicious library path.
///
/// Returns `true` when any library in the colon/space-separated list resides
/// outside standard system library directories or in staging directories.
pub fn classify_ld_preload(value: &str) -> bool {
    todo!("classify_ld_preload({value:?})")
}

// ---------------------------------------------------------------------------
// Shared library classification
// ---------------------------------------------------------------------------

/// Classify whether a mapped library path is suspicious.
///
/// Flags deleted libraries, libraries in `/tmp`, `/dev/shm`, and libraries
/// with suspicious extensions.
pub fn classify_library(lib_path: &str) -> bool {
    todo!("classify_library({lib_path:?})")
}

// ---------------------------------------------------------------------------
// memfd classification
// ---------------------------------------------------------------------------

/// Classify whether a `memfd_create` file is suspicious.
///
/// Executable anonymous memory is always suspicious. Empty names and names
/// matching known rootkit patterns are also flagged.
pub fn classify_memfd(name: &str, is_executable: bool) -> bool {
    todo!("classify_memfd({name:?}, {is_executable})")
}

// ---------------------------------------------------------------------------
// Kernel module visibility classification
// ---------------------------------------------------------------------------

/// Classify whether a kernel module is hidden by cross-referencing three views.
///
/// Returns `true` when the module is present in at least one view but absent
/// from at least one other (partial visibility = hidden).
pub fn classify_module_visibility(
    in_module_list: bool,
    in_kobj_list: bool,
    in_memory_map: bool,
) -> bool {
    todo!("classify_module_visibility({in_module_list}, {in_kobj_list}, {in_memory_map})")
}

// ---------------------------------------------------------------------------
// Mount classification
// ---------------------------------------------------------------------------

/// Classify whether a mount entry is suspicious.
///
/// Flags unusual tmpfs/ramfs mounts and overlay mounts outside known container
/// runtime paths.
pub fn classify_mount(fs_type: &str, dev_name: &str, mnt_root: &str) -> bool {
    todo!("classify_mount({fs_type:?}, {dev_name:?}, {mnt_root:?})")
}

// ---------------------------------------------------------------------------
// OOM victim classification
// ---------------------------------------------------------------------------

/// Classify whether an OOM-killed process is suspicious.
///
/// Flags processes with names matching known attacker tools and processes with
/// very low PIDs (< 100).
pub fn classify_oom_victim(comm: &str, pid: u32) -> bool {
    todo!("classify_oom_victim({comm:?}, {pid})")
}

// ---------------------------------------------------------------------------
// PAM hook classification
// ---------------------------------------------------------------------------

/// Classify whether a PAM library path is suspicious.
///
/// Returns `true` when the path contains "pam" (case-insensitive) and does not
/// start with a known system library directory.
pub fn classify_pam_hook(path: &str) -> bool {
    todo!("classify_pam_hook({path:?})")
}

// ---------------------------------------------------------------------------
// perf_event classification
// ---------------------------------------------------------------------------

/// Classify whether a `perf_event` is suspicious.
///
/// Flags RAW PMU access (type 4) and certain cache event configurations (type 3).
pub fn classify_perf_event(event_type: u32, config: u64) -> bool {
    todo!("classify_perf_event({event_type}, {config})")
}

// ---------------------------------------------------------------------------
// psaux classification
// ---------------------------------------------------------------------------

/// Classify whether process auxiliary state is suspicious.
///
/// Flags impossible combinations: zombie root processes, non-root kernel
/// threads, and processes with extremely large virtual address spaces.
pub fn classify_psaux(state: u64, uid: u32, flags: u64, vsize: u64) -> bool {
    todo!("classify_psaux({state}, {uid}, {flags}, {vsize})")
}

// ---------------------------------------------------------------------------
// ptrace classification
// ---------------------------------------------------------------------------

/// Classify whether a ptrace relationship is suspicious.
///
/// Flags tracers with empty names, tracers of high-value system processes, and
/// self-tracing processes.
pub fn classify_ptrace(tracer_name: &str, tracee_name: &str) -> bool {
    todo!("classify_ptrace({tracer_name:?}, {tracee_name:?})")
}

// ---------------------------------------------------------------------------
// Raw socket classification
// ---------------------------------------------------------------------------

/// Classify whether a raw socket is suspicious.
///
/// Promiscuous sockets are always suspicious. AF_PACKET sockets owned by
/// non-standard utilities are flagged.
pub fn classify_raw_socket(comm: &str, socket_type: &str, is_promiscuous: bool) -> bool {
    todo!("classify_raw_socket({comm:?}, {socket_type:?}, {is_promiscuous})")
}

// ---------------------------------------------------------------------------
// Signal handler classification
// ---------------------------------------------------------------------------

/// Classify whether a signal handler configuration is suspicious.
///
/// Flags SIG_IGN for SIGTERM/SIGHUP (anti-termination), custom handlers for
/// SIGSEGV (self-healing), and any SIGKILL handler (rootkit indicator).
pub fn classify_signal_handler(signal: u32, handler: u64) -> bool {
    todo!("classify_signal_handler({signal}, {handler})")
}

// ---------------------------------------------------------------------------
// systemd unit classification
// ---------------------------------------------------------------------------

/// Classify whether a systemd unit is suspicious.
///
/// Returns `false` for known-safe unit names and safe `ExecStart` prefixes.
pub fn classify_systemd_unit(unit_name: &str, exec_start: &str) -> bool {
    todo!("classify_systemd_unit({unit_name:?}, {exec_start:?})")
}

// ---------------------------------------------------------------------------
// tmpfs file classification
// ---------------------------------------------------------------------------

/// Classify whether a tmpfs file is suspicious.
///
/// Flags executable regular files and hidden files (names starting with `.`).
pub fn classify_tmpfs_file(filename: &str, mode: u32) -> bool {
    todo!("classify_tmpfs_file({filename:?}, {mode})")
}

// ---------------------------------------------------------------------------
// Unix socket classification
// ---------------------------------------------------------------------------

/// Classify whether a Unix domain socket is suspicious.
///
/// Flags abstract sockets owned by high-uid processes and sockets in staging
/// directories.
pub fn classify_unix_socket(path: &str, owner_pid: u32) -> bool {
    todo!("classify_unix_socket({path:?}, {owner_pid})")
}

// ---------------------------------------------------------------------------
// Zombie/orphan classification
// ---------------------------------------------------------------------------

/// Classify whether a zombie or orphan process is suspicious.
///
/// Flags zombie processes re-parented to init and orphan processes with names
/// matching known attacker tools.
pub fn classify_zombie_orphan(is_zombie: bool, is_orphan: bool, ppid: u32, comm: &str) -> bool {
    todo!("classify_zombie_orphan({is_zombie}, {is_orphan}, {ppid}, {comm:?})")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- classify_bpf_program ---

    #[test]
    fn heuristics_bpf_kprobe_is_suspicious() {
        assert!(classify_bpf_program("kprobe", "my_hook"));
    }

    #[test]
    fn heuristics_bpf_lsm_is_suspicious() {
        assert!(classify_bpf_program("lsm", ""));
    }

    #[test]
    fn heuristics_bpf_xdp_benign() {
        assert!(!classify_bpf_program("xdp", "firewall"));
    }

    #[test]
    fn heuristics_bpf_unnamed_tracing_suspicious() {
        assert!(classify_bpf_program("tracing", ""));
    }

    #[test]
    fn heuristics_bpf_named_tracing_benign() {
        assert!(!classify_bpf_program("tracing", "named_prog"));
    }

    // --- classify_capabilities ---

    #[test]
    fn heuristics_capabilities_root_never_suspicious() {
        let (susp, names) = classify_capabilities(u64::MAX, 0);
        assert!(!susp);
        assert!(names.is_empty());
    }

    #[test]
    fn heuristics_capabilities_non_root_sys_admin_suspicious() {
        let cap_sys_admin: u64 = 1 << 21;
        let (susp, names) = classify_capabilities(cap_sys_admin, 1000);
        assert!(susp);
        assert!(!names.is_empty());
    }

    #[test]
    fn heuristics_capabilities_non_root_no_caps_benign() {
        let (susp, names) = classify_capabilities(0, 1000);
        assert!(!susp);
        assert!(names.is_empty());
    }

    // --- classify_cgroup ---

    #[test]
    fn heuristics_cgroup_docker_detected() {
        let (in_container, id) = classify_cgroup("/docker/abc123def456");
        assert!(in_container);
        assert_eq!(id, "abc123def456");
    }

    #[test]
    fn heuristics_cgroup_bare_root_not_container() {
        let (in_container, id) = classify_cgroup("/");
        assert!(!in_container);
        assert!(id.is_empty());
    }

    // --- classify_afinfo_hook ---

    #[test]
    fn heuristics_afinfo_null_not_hooked() {
        assert!(!classify_afinfo_hook(0, 0xffff0000, 0xffff8000));
    }

    #[test]
    fn heuristics_afinfo_in_range_benign() {
        assert!(!classify_afinfo_hook(0xffff1000, 0xffff0000, 0xffff8000));
    }

    #[test]
    fn heuristics_afinfo_outside_range_suspicious() {
        assert!(classify_afinfo_hook(0x0000_dead_beef, 0xffff0000, 0xffff8000));
    }

    // --- classify_shared_creds ---

    #[test]
    fn heuristics_shared_creds_userspace_shares_with_init_suspicious() {
        assert!(classify_shared_creds(500, &[1], 1000));
    }

    #[test]
    fn heuristics_shared_creds_empty_list_benign() {
        assert!(!classify_shared_creds(500, &[], 1000));
    }

    #[test]
    fn heuristics_shared_creds_kernel_thread_shares_with_init_benign() {
        // pid 2 (kthreadd), uid 0 shares with init — expected
        assert!(!classify_shared_creds(2, &[1], 0));
    }

    // --- classify_idt_entry ---

    #[test]
    fn heuristics_idt_null_not_hooked() {
        assert!(!classify_idt_entry(0, 0xffff0000, 0xffff8000));
    }

    #[test]
    fn heuristics_idt_in_kernel_range_benign() {
        assert!(!classify_idt_entry(0xffff2000, 0xffff0000, 0xffff8000));
    }

    #[test]
    fn heuristics_idt_outside_range_suspicious() {
        assert!(classify_idt_entry(0x1234, 0xffff0000, 0xffff8000));
    }

    // --- classify_container_escape ---

    #[test]
    fn heuristics_container_escape_namespace_mismatch_suspicious() {
        assert!(classify_container_escape("bash", "namespace_mismatch"));
    }

    #[test]
    fn heuristics_container_escape_kernel_thread_benign() {
        assert!(!classify_container_escape("kworker/0:0", "namespace_mismatch"));
    }

    #[test]
    fn heuristics_container_escape_unknown_indicator_benign() {
        assert!(!classify_container_escape("bash", "some_other_thing"));
    }

    // --- classify_deleted_exe ---

    #[test]
    fn heuristics_deleted_exe_not_deleted_benign() {
        assert!(!classify_deleted_exe("/usr/bin/bash", "bash"));
    }

    #[test]
    fn heuristics_deleted_exe_suspicious() {
        assert!(classify_deleted_exe("/tmp/evil (deleted)", "evil"));
    }

    #[test]
    fn heuristics_deleted_exe_empty_comm_benign() {
        assert!(!classify_deleted_exe("/tmp/x (deleted)", ""));
    }

    // --- classify_hidden_dentry ---

    #[test]
    fn heuristics_hidden_dentry_nlink_zero_suspicious() {
        assert!(classify_hidden_dentry(0, "normal.txt"));
    }

    #[test]
    fn heuristics_hidden_dentry_empty_filename_benign() {
        assert!(!classify_hidden_dentry(0, ""));
    }

    #[test]
    fn heuristics_hidden_dentry_linked_no_suspicious_ext_benign() {
        assert!(!classify_hidden_dentry(1, "readme.txt"));
    }

    // --- classify_ebpf_map ---

    #[test]
    fn heuristics_ebpf_map_ringbuf_suspicious() {
        // map_type 26 = ringbuf — high-risk exfiltration channel
        assert!(classify_ebpf_map(26, "benign_name", 8));
    }

    #[test]
    fn heuristics_ebpf_map_perf_event_array_suspicious() {
        assert!(classify_ebpf_map(3, "benign_name", 8));
    }

    #[test]
    fn heuristics_ebpf_map_hash_benign_name_benign() {
        // map_type 1 = hash, benign name
        assert!(!classify_ebpf_map(1, "counters", 8));
    }

    // --- classify_ftrace_hook ---

    #[test]
    fn heuristics_ftrace_in_text_benign() {
        assert!(!classify_ftrace_hook(0x1000, 0x1000, 0x2000));
    }

    #[test]
    fn heuristics_ftrace_outside_text_suspicious() {
        assert!(classify_ftrace_hook(0x500, 0x1000, 0x2000));
    }

    // --- classify_futex ---

    #[test]
    fn heuristics_futex_high_waiter_count_suspicious() {
        assert!(classify_futex(0x1000, 0, 1001));
    }

    #[test]
    fn heuristics_futex_normal_benign() {
        assert!(!classify_futex(0x1000, 0, 5));
    }

    #[test]
    fn heuristics_futex_kernel_key_userspace_owner_suspicious() {
        assert!(classify_futex(0xffff_0000_0000, 1234, 0));
    }

    // --- classify_io_uring ---

    #[test]
    fn heuristics_io_uring_no_seccomp_benign() {
        assert!(!classify_io_uring(&[1, 2, 3], 0));
    }

    #[test]
    fn heuristics_io_uring_no_opcodes_benign() {
        assert!(!classify_io_uring(&[], 1));
    }

    // --- classify_iomem ---

    #[test]
    fn heuristics_iomem_kernel_code_name_benign() {
        assert!(!classify_iomem("Kernel code", 0xffff_ffff_8100_0000, 0xffff_ffff_8180_0000));
    }

    #[test]
    fn heuristics_iomem_empty_name_small_region_benign() {
        // Under 1 MiB — not suspicious
        assert!(!classify_iomem("", 0, 1024));
    }

    #[test]
    fn heuristics_iomem_empty_name_large_region_suspicious() {
        assert!(classify_iomem("", 0, 2 * 1024 * 1024));
    }

    // --- classify_kernel_timer ---

    #[test]
    fn heuristics_kernel_timer_null_benign() {
        assert!(!classify_kernel_timer(0, 0xffff0000, 0xffff8000));
    }

    #[test]
    fn heuristics_kernel_timer_in_range_benign() {
        assert!(!classify_kernel_timer(0xffff1000, 0xffff0000, 0xffff8000));
    }

    #[test]
    fn heuristics_kernel_timer_outside_range_suspicious() {
        assert!(classify_kernel_timer(0x1234, 0xffff0000, 0xffff8000));
    }

    // --- classify_notifier ---

    #[test]
    fn heuristics_notifier_in_text_benign() {
        assert!(!classify_notifier(0x1000, 0x1000, 0x2000));
    }

    #[test]
    fn heuristics_notifier_below_stext_suspicious() {
        assert!(classify_notifier(0x500, 0x1000, 0x2000));
    }

    // --- classify_kmsg ---

    #[test]
    fn heuristics_kmsg_normal_message_benign() {
        assert!(!classify_kmsg("USB device connected"));
    }

    // --- classify_kthread ---

    #[test]
    fn heuristics_kthread_empty_name_suspicious() {
        let (susp, reason) = classify_kthread("", 0xffff_8000_0000);
        assert!(susp);
        assert!(reason.is_some());
    }

    #[test]
    fn heuristics_kthread_named_kernel_fn_benign() {
        let (susp, _) = classify_kthread("kworker/0:0", 0xffff_8000_1234);
        assert!(!susp);
    }

    // --- classify_ld_preload ---

    #[test]
    fn heuristics_ld_preload_tmp_path_suspicious() {
        assert!(classify_ld_preload("/tmp/evil.so"));
    }

    #[test]
    fn heuristics_ld_preload_system_lib_benign() {
        assert!(!classify_ld_preload("/usr/lib/libfoo.so"));
    }

    // --- classify_library ---

    #[test]
    fn heuristics_library_deleted_suspicious() {
        assert!(classify_library("/usr/lib/libfoo.so (deleted)"));
    }

    #[test]
    fn heuristics_library_normal_benign() {
        assert!(!classify_library("/usr/lib/libc.so.6"));
    }

    #[test]
    fn heuristics_library_tmp_suspicious() {
        assert!(classify_library("/tmp/inject.so"));
    }

    // --- classify_memfd ---

    #[test]
    fn heuristics_memfd_executable_suspicious() {
        assert!(classify_memfd("legit_name", true));
    }

    #[test]
    fn heuristics_memfd_empty_name_suspicious() {
        assert!(classify_memfd("", false));
    }

    // --- classify_module_visibility ---

    #[test]
    fn heuristics_module_visibility_all_present_benign() {
        assert!(!classify_module_visibility(true, true, true));
    }

    #[test]
    fn heuristics_module_visibility_partial_hidden() {
        assert!(classify_module_visibility(true, false, true));
    }

    #[test]
    fn heuristics_module_visibility_all_absent_benign() {
        // Not found anywhere — not suspicious, just absent
        assert!(!classify_module_visibility(false, false, false));
    }

    // --- classify_mount ---

    #[test]
    fn heuristics_mount_known_tmpfs_root_benign() {
        assert!(!classify_mount("tmpfs", "tmpfs", "/tmp"));
    }

    #[test]
    fn heuristics_mount_unknown_tmpfs_suspicious() {
        assert!(classify_mount("tmpfs", "tmpfs", "/secret_staging"));
    }

    #[test]
    fn heuristics_mount_ext4_benign() {
        assert!(!classify_mount("ext4", "/dev/sda1", "/"));
    }

    // --- classify_oom_victim ---

    #[test]
    fn heuristics_oom_victim_low_pid_suspicious() {
        assert!(classify_oom_victim("bash", 5));
    }

    #[test]
    fn heuristics_oom_victim_normal_benign() {
        assert!(!classify_oom_victim("chrome", 5000));
    }

    // --- classify_pam_hook ---

    #[test]
    fn heuristics_pam_hook_empty_benign() {
        assert!(!classify_pam_hook(""));
    }

    #[test]
    fn heuristics_pam_hook_system_lib_benign() {
        assert!(!classify_pam_hook("/lib/x86_64-linux-gnu/libpam.so.0"));
    }

    #[test]
    fn heuristics_pam_hook_tmp_suspicious() {
        assert!(classify_pam_hook("/tmp/fakepam.so"));
    }

    // --- classify_perf_event ---

    #[test]
    fn heuristics_perf_event_raw_pmu_suspicious() {
        assert!(classify_perf_event(4, 0));
    }

    #[test]
    fn heuristics_perf_event_software_benign() {
        assert!(!classify_perf_event(1, 0));
    }

    // --- classify_psaux ---

    #[test]
    fn heuristics_psaux_zombie_root_suspicious() {
        // state=16 (zombie), uid=0
        assert!(classify_psaux(16, 0, 0, 0));
    }

    #[test]
    fn heuristics_psaux_normal_process_benign() {
        assert!(!classify_psaux(1, 1000, 0, 4096));
    }

    // --- classify_ptrace ---

    #[test]
    fn heuristics_ptrace_empty_tracer_suspicious() {
        assert!(classify_ptrace("", "bash"));
    }

    #[test]
    fn heuristics_ptrace_gdb_tracing_bash_benign() {
        assert!(!classify_ptrace("gdb", "bash"));
    }

    // --- classify_raw_socket ---

    #[test]
    fn heuristics_raw_socket_promiscuous_suspicious() {
        assert!(classify_raw_socket("tcpdump", "AF_PACKET", true));
    }

    #[test]
    fn heuristics_raw_socket_tcpdump_not_promiscuous_benign() {
        assert!(!classify_raw_socket("tcpdump", "AF_PACKET", false));
    }

    // --- classify_signal_handler ---

    #[test]
    fn heuristics_signal_handler_sigterm_ignored_suspicious() {
        // handler=1 (SIG_IGN) for SIGTERM (15)
        assert!(classify_signal_handler(15, 1));
    }

    #[test]
    fn heuristics_signal_handler_sigterm_default_benign() {
        assert!(!classify_signal_handler(15, 0));
    }

    #[test]
    fn heuristics_signal_handler_sigkill_nonzero_suspicious() {
        assert!(classify_signal_handler(9, 0x1234));
    }

    // --- classify_systemd_unit ---

    #[test]
    fn heuristics_systemd_unit_suspicious_exec_start() {
        assert!(classify_systemd_unit("evil.service", "/tmp/backdoor.sh"));
    }

    // --- classify_tmpfs_file ---

    #[test]
    fn heuristics_tmpfs_file_executable_regular_suspicious() {
        // S_IFREG | executable: 0o100755
        assert!(classify_tmpfs_file("payload", 0o100_755));
    }

    #[test]
    fn heuristics_tmpfs_file_hidden_suspicious() {
        assert!(classify_tmpfs_file(".hidden", 0o100_644));
    }

    #[test]
    fn heuristics_tmpfs_file_normal_benign() {
        assert!(!classify_tmpfs_file("readme.txt", 0o100_644));
    }

    // --- classify_unix_socket ---

    #[test]
    fn heuristics_unix_socket_abstract_high_uid_suspicious() {
        // Abstract socket (empty path), owner_pid >= 1000
        assert!(classify_unix_socket("", 1234));
    }

    #[test]
    fn heuristics_unix_socket_system_path_benign() {
        assert!(!classify_unix_socket("/var/run/docker.sock", 500));
    }

    #[test]
    fn heuristics_unix_socket_tmp_suspicious() {
        assert!(classify_unix_socket("/tmp/evil.sock", 500));
    }

    // --- classify_zombie_orphan ---

    #[test]
    fn heuristics_zombie_orphan_reparented_to_init_suspicious() {
        assert!(classify_zombie_orphan(true, false, 1, "bash"));
    }

    #[test]
    fn heuristics_zombie_orphan_normal_benign() {
        assert!(!classify_zombie_orphan(false, false, 1234, "chrome"));
    }
}
