#![deny(unsafe_code)]

mod archive;
mod os_detect;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use comfy_table::{presets::UTF8_FULL_CONDENSED, Table};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

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
        memf mod memdump.dmp --symbols ntkrnlmp.json\n  \
        memf net memdump.dmp --symbols ntkrnlmp.json --output csv\n  \
        memf lib memdump.dmp --symbols ntkrnlmp.json --pid 1234\n  \
        memf maps memdump.lime --symbols linux.json\n  \
        memf files memdump.lime --symbols linux.json\n  \
        memf envvars memdump.lime --symbols linux.json --output json\n  \
        memf envvars memdump.dmp --symbols ntkrnlmp.json\n  \
        memf cmdline memdump.dmp --symbols ntkrnlmp.json\n  \
        memf ps memdump.dmp --symbols ntkrnlmp.json --tree\n  \
        memf ps memdump.dmp --symbols ntkrnlmp.json --masquerade\n  \
        memf malfind memdump.lime --symbols linux.json\n  \
        memf mounts memdump.lime --symbols linux.json\n  \
        memf mod memdump.lime --symbols linux.json --check-syscalls\n  \
        memf mod memdump.lime --symbols linux.json --check-hooks\n  \
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
    /// List processes (and optionally threads) from a memory dump.
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

        /// Also enumerate threads for each process (Windows only).
        #[arg(long)]
        threads: bool,

        /// Filter by process ID.
        #[arg(long)]
        pid: Option<u64>,

        /// Display processes as a tree (Windows only).
        #[arg(long)]
        tree: bool,

        /// Check for PEB masquerade (EPROCESS vs PEB image name mismatch). Windows only.
        #[arg(long)]
        masquerade: bool,
    },
    /// List loaded kernel modules (Linux) or drivers (Windows).
    ///
    /// With --check-syscalls or --check-hooks (Linux), also runs integrity
    /// checks on the syscall table or kernel function prologues.
    /// With --check-irp (Windows, future), checks driver IRP dispatch tables.
    Mod {
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
        check_syscalls: bool,

        /// Check kernel functions for inline hooks (Linux only).
        #[arg(long)]
        check_hooks: bool,

        /// Check driver IRP dispatch table for hooks (Windows only).
        #[arg(long)]
        check_irp: bool,
    },
    /// List network connections from a memory dump.
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
    },
    /// List loaded libraries (DLLs, .so, dylibs) for a process.
    Lib {
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

        /// Process ID to list libraries for (required).
        #[arg(long)]
        pid: u64,
    },
    /// List process virtual memory areas (VMAs / memory maps). Linux only.
    Maps {
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
    },
    /// List open file descriptors for all processes. Linux only.
    Files {
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
    },
    /// List process environment variables (Linux and Windows).
    Envvars {
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
    },
    /// Extract process command lines from PEB (Windows only).
    Cmdline {
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
    },
    /// Detect suspicious memory regions (anonymous RWX). Linux only.
    Malfind {
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
    },
    /// List mounted filesystems. Linux only.
    Mounts {
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
    },
    /// Recover bash command history from process heaps. Linux only.
    #[command(name = "bash-history")]
    BashHistory {
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
    },
    /// Cross-view hidden process detection. Linux only.
    Psxview {
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
    },
    /// Check TTY driver operations for hooks. Linux only.
    #[command(name = "check-tty")]
    CheckTty {
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
    },
    /// Extract ELF headers from process memory. Linux only.
    Elfinfo {
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
    },
    /// Detect hidden kernel modules. Linux only.
    #[command(name = "check-modules")]
    CheckModules {
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
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Csv,
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
                resolved.is_extracted(),
            )
        }
        Commands::Mod {
            dump,
            symbols,
            output,
            cr3,
            check_syscalls,
            check_hooks,
            check_irp,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_mod(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                check_syscalls,
                check_hooks,
                check_irp,
                resolved.is_extracted(),
            )
        }
        Commands::Net {
            dump,
            symbols,
            output,
            cr3,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_net(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                resolved.is_extracted(),
            )
        }
        Commands::Lib {
            dump,
            symbols,
            output,
            cr3,
            pid,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_lib(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                pid,
                resolved.is_extracted(),
            )
        }
        Commands::Maps {
            dump,
            symbols,
            output,
            cr3,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_maps(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                resolved.is_extracted(),
            )
        }
        Commands::Files {
            dump,
            symbols,
            output,
            cr3,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_files(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                resolved.is_extracted(),
            )
        }
        Commands::Envvars {
            dump,
            symbols,
            output,
            cr3,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_envvars(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                resolved.is_extracted(),
            )
        }
        Commands::Cmdline {
            dump,
            symbols,
            output,
            cr3,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_cmdline(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                resolved.is_extracted(),
            )
        }
        Commands::Malfind {
            dump,
            symbols,
            output,
            cr3,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_malfind(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                resolved.is_extracted(),
            )
        }
        Commands::Mounts {
            dump,
            symbols,
            output,
            cr3,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_mounts(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                resolved.is_extracted(),
            )
        }
        Commands::BashHistory {
            dump,
            symbols,
            output,
            cr3,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_bash_history(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                resolved.is_extracted(),
            )
        }
        Commands::Psxview {
            dump,
            symbols,
            output,
            cr3,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_psxview(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                resolved.is_extracted(),
            )
        }
        Commands::CheckTty {
            dump,
            symbols,
            output,
            cr3,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_check_tty(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                resolved.is_extracted(),
            )
        }
        Commands::Elfinfo {
            dump,
            symbols,
            output,
            cr3,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_elfinfo(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
                resolved.is_extracted(),
            )
        }
        Commands::CheckModules {
            dump,
            symbols,
            output,
            cr3,
        } => {
            let resolved = archive::resolve_dump(&dump)?;
            cmd_check_modules(
                resolved.path(),
                symbols.as_deref(),
                output,
                cr3,
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
    ObjectReader<Box<dyn PhysicalMemoryProvider>>,
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
// cmd_ps — dispatch to Linux or Windows walker
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn cmd_ps(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    threads: bool,
    pid_filter: Option<u64>,
    tree: bool,
    masquerade: bool,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    match ctx.os {
        OsProfile::Linux => {
            if threads {
                anyhow::bail!("--threads is not yet supported for Linux dumps");
            }
            if tree {
                anyhow::bail!("--tree is not yet supported for Linux dumps");
            }
            if masquerade {
                anyhow::bail!("--masquerade is only supported for Windows dumps");
            }
            let procs = memf_linux::process::walk_processes(&reader)
                .context("failed to walk Linux processes")?;
            print_linux_processes(&procs, output);
        }
        OsProfile::Windows => {
            let ps_head = ctx
                .ps_active_process_head
                .context("missing PsActiveProcessHead; provide via symbols or dump metadata")?;
            let procs = memf_windows::process::walk_processes(&reader, ps_head)
                .context("failed to walk Windows processes")?;

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
        }
        OsProfile::MacOs => anyhow::bail!("macOS process walking not yet supported"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_mod — Linux kernel modules or Windows drivers
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn cmd_mod(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    check_syscalls: bool,
    check_hooks: bool,
    check_irp: bool,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    match ctx.os {
        OsProfile::Linux => {
            if check_irp {
                anyhow::bail!("--check-irp is only available for Windows memory dumps");
            }
            let mods = memf_linux::modules::walk_modules(&reader)
                .context("failed to walk Linux modules")?;
            print_linux_modules(&mods, output);
            if check_syscalls {
                let entries = memf_linux::syscalls::check_syscall_table(&reader)
                    .context("failed to check syscall table")?;
                print_syscalls(&entries, output);
            }
            if check_hooks {
                let entries = memf_linux::check_hooks::check_inline_hooks(&reader)
                    .context("failed to check inline hooks")?;
                print_check_hooks(&entries, output);
            }
        }
        OsProfile::Windows => {
            if check_syscalls {
                anyhow::bail!("--check-syscalls is only available for Linux memory dumps");
            }
            if check_hooks {
                anyhow::bail!("--check-hooks is only available for Linux memory dumps");
            }
            let mod_list = ctx
                .ps_loaded_module_list
                .context("missing PsLoadedModuleList; provide via symbols or dump metadata")?;
            let drivers = memf_windows::driver::walk_drivers(&reader, mod_list)
                .context("failed to walk Windows drivers")?;
            print_windows_drivers(&drivers, output);
            if check_irp {
                anyhow::bail!(
                    "--check-irp requires _DRIVER_OBJECT enumeration via pool scanning (not yet implemented)"
                );
            }
        }
        OsProfile::MacOs => anyhow::bail!("macOS module walking not yet supported"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_net — Linux only for now
// ---------------------------------------------------------------------------

fn cmd_net(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    match ctx.os {
        OsProfile::Linux => {
            let conns = memf_linux::network::walk_connections(&reader)
                .context("failed to walk Linux connections")?;
            print_connections(&conns, output);
        }
        OsProfile::Windows => {
            anyhow::bail!("Windows network connection walking not yet supported (Phase 3E)")
        }
        OsProfile::MacOs => anyhow::bail!("macOS network walking not yet supported"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_lib — per-process loaded libraries (DLLs, .so, dylibs)
// ---------------------------------------------------------------------------

fn cmd_lib(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    pid: u64,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    if ctx.os != OsProfile::Windows {
        anyhow::bail!("memf lib currently requires a Windows memory dump");
    }
    let ps_head = ctx
        .ps_active_process_head
        .context("missing PsActiveProcessHead")?;
    let procs = memf_windows::process::walk_processes(&reader, ps_head)
        .context("failed to walk processes")?;

    let target = procs
        .iter()
        .find(|p| p.pid == pid)
        .with_context(|| format!("process with PID {pid} not found"))?;

    if target.peb_addr == 0 {
        anyhow::bail!("process PID {pid} has no PEB (kernel process?)");
    }

    let dlls = memf_windows::dll::walk_dlls(&reader, target.peb_addr)
        .with_context(|| format!("failed to walk DLLs for PID {pid}"))?;
    print_libs(&dlls, output);
    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_maps — Linux process VMAs
// ---------------------------------------------------------------------------

fn cmd_maps(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    if ctx.os != OsProfile::Linux {
        anyhow::bail!("memf maps currently requires a Linux memory dump");
    }
    let vmas = memf_linux::maps::walk_maps(&reader).context("failed to walk Linux VMAs")?;
    print_vmas(&vmas, output);
    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_files — Linux open file descriptors
// ---------------------------------------------------------------------------

fn cmd_files(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    if ctx.os != OsProfile::Linux {
        anyhow::bail!("memf files currently requires a Linux memory dump");
    }
    let fds =
        memf_linux::files::walk_files(&reader).context("failed to walk Linux file descriptors")?;
    print_file_descriptors(&fds, output);
    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_envvars — process environment variables (Linux and Windows)
// ---------------------------------------------------------------------------

fn cmd_envvars(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    match ctx.os {
        OsProfile::Linux => {
            let vars = memf_linux::envvars::walk_envvars(&reader)
                .context("failed to walk Linux environment variables")?;
            print_envvars(&vars, output);
        }
        OsProfile::Windows => {
            let ps_head = ctx
                .ps_active_process_head
                .context("missing PsActiveProcessHead; provide via symbols or dump metadata")?;
            let vars = memf_windows::envvars::walk_envvars(&reader, ps_head)
                .context("failed to walk Windows environment variables")?;
            print_windows_envvars(&vars, output);
        }
        OsProfile::MacOs => anyhow::bail!("macOS environment variable walking not yet supported"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_cmdline — Windows process command lines
// ---------------------------------------------------------------------------

fn cmd_cmdline(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    match ctx.os {
        OsProfile::Windows => {
            let ps_head = ctx
                .ps_active_process_head
                .context("missing PsActiveProcessHead; provide via symbols or dump metadata")?;
            let cmdlines = memf_windows::cmdline::walk_cmdlines(&reader, ps_head)
                .context("failed to walk Windows command lines")?;
            print_windows_cmdlines(&cmdlines, output);
        }
        _ => anyhow::bail!("memf cmdline currently requires a Windows memory dump"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_malfind — suspicious memory regions
// ---------------------------------------------------------------------------

fn cmd_malfind(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    if ctx.os != OsProfile::Linux {
        anyhow::bail!("memf malfind currently requires a Linux memory dump");
    }
    let findings = memf_linux::malfind::scan_malfind(&reader)
        .context("failed to scan for suspicious memory regions")?;
    print_malfind(&findings, output);
    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_mounts — Linux mounted filesystems
// ---------------------------------------------------------------------------

fn cmd_mounts(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    if ctx.os != OsProfile::Linux {
        anyhow::bail!("memf mounts currently requires a Linux memory dump");
    }
    let mounts = memf_linux::fs::walk_filesystems(&reader)
        .context("failed to walk Linux mounted filesystems")?;
    print_mounts(&mounts, output);
    Ok(())
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// cmd_bash_history — recover bash command history from process heaps
// ---------------------------------------------------------------------------

fn cmd_bash_history(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    if ctx.os != OsProfile::Linux {
        anyhow::bail!("memf bash-history currently requires a Linux memory dump");
    }
    let entries =
        memf_linux::bash::walk_bash_history(&reader).context("failed to recover bash history")?;
    print_bash_history(&entries, output);
    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_psxview — cross-view hidden process detection
// ---------------------------------------------------------------------------

fn cmd_psxview(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    if ctx.os != OsProfile::Linux {
        anyhow::bail!("memf psxview currently requires a Linux memory dump");
    }
    let entries = memf_linux::psxview::walk_psxview(&reader).context("failed to run psxview")?;
    print_psxview(&entries, output);
    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_check_tty — check TTY driver operations for hooks
// ---------------------------------------------------------------------------

fn cmd_check_tty(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    if ctx.os != OsProfile::Linux {
        anyhow::bail!("memf check-tty currently requires a Linux memory dump");
    }
    let entries =
        memf_linux::tty_check::check_tty_hooks(&reader).context("failed to check TTY hooks")?;
    print_tty_check(&entries, output);
    Ok(())
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// cmd_elfinfo — extract ELF headers from process memory
// ---------------------------------------------------------------------------

fn cmd_elfinfo(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    if ctx.os != OsProfile::Linux {
        anyhow::bail!("memf elfinfo currently requires a Linux memory dump");
    }
    let entries =
        memf_linux::elfinfo::walk_elfinfo(&reader).context("failed to extract ELF info")?;
    print_elfinfo(&entries, output);
    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_check_modules — detect hidden kernel modules
// ---------------------------------------------------------------------------

fn cmd_check_modules(
    dump: &Path,
    symbols_path: Option<&Path>,
    output: OutputFormat,
    cr3_override: Option<u64>,
    raw_fallback: bool,
) -> Result<()> {
    let (ctx, reader) = setup_analysis(dump, symbols_path, cr3_override, raw_fallback)?;
    if ctx.os != OsProfile::Linux {
        anyhow::bail!("memf check-modules currently requires a Linux memory dump");
    }
    let entries = memf_linux::check_modules::check_hidden_modules(&reader)
        .context("failed to check hidden modules")?;
    print_check_modules(&entries, output);
    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_strings (unchanged)
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

fn print_linux_processes(procs: &[memf_linux::ProcessInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["PID", "PPID", "Name", "State", "Vaddr"]);
            for p in procs {
                table.add_row(vec![
                    format!("{}", p.pid),
                    format!("{}", p.ppid),
                    p.comm.clone(),
                    format!("{}", p.state),
                    format!("{:#x}", p.vaddr),
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
                    "name": p.comm,
                    "state": format!("{}", p.state),
                    "vaddr": format!("{:#x}", p.vaddr),
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,ppid,name,state,vaddr");
            for p in procs {
                println!("{},{},{},{},{:#x}", p.pid, p.ppid, p.comm, p.state, p.vaddr);
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
            table.set_header(vec!["PID", "PPID", "Image Name", "Create Time", "CR3"]);
            for p in procs {
                table.add_row(vec![
                    format!("{}", p.pid),
                    format!("{}", p.ppid),
                    p.image_name.clone(),
                    format!("{:#x}", p.create_time),
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
                    "create_time": format!("{:#x}", p.create_time),
                    "cr3": format!("{:#x}", p.cr3),
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,ppid,image_name,create_time,cr3");
            for p in procs {
                println!(
                    "{},{},{},{:#x},{:#x}",
                    p.pid, p.ppid, p.image_name, p.create_time, p.cr3
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
            table.set_header(vec!["PID", "PPID", "Image Name", "Create Time", "CR3"]);
            for e in entries {
                let indent = "  ".repeat(e.depth as usize);
                let name = format!("{}{}", indent, e.process.image_name);
                table.add_row(vec![
                    format!("{}", e.process.pid),
                    format!("{}", e.process.ppid),
                    name,
                    format!("{:#x}", e.process.create_time),
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
                    "create_time": format!("{:#x}", e.process.create_time),
                    "cr3": format!("{:#x}", e.process.cr3),
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("pid,ppid,image_name,depth,create_time,cr3");
            for e in entries {
                println!(
                    "{},{},{},{},{:#x},{:#x}",
                    e.process.pid,
                    e.process.ppid,
                    e.process.image_name,
                    e.depth,
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

// ---------------------------------------------------------------------------
// Output formatters — threads
// ---------------------------------------------------------------------------

fn print_threads(threads: &[memf_windows::WinThreadInfo], output: OutputFormat) {
    match output {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["TID", "PID", "Start Address", "State", "Create Time"]);
            for t in threads {
                table.add_row(vec![
                    format!("{}", t.tid),
                    format!("{}", t.pid),
                    format!("{:#x}", t.start_address),
                    format!("{}", t.state),
                    format!("{:#x}", t.create_time),
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
                    "create_time": format!("{:#x}", t.create_time),
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("tid,pid,start_address,state,create_time");
            for t in threads {
                println!(
                    "{},{},{:#x},{},{:#x}",
                    t.tid, t.pid, t.start_address, t.state, t.create_time
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output formatters — libraries (DLLs, .so, dylibs)
// ---------------------------------------------------------------------------

fn print_libs(dlls: &[memf_windows::WinDllInfo], output: OutputFormat) {
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
            println!("\nTotal: {} DLLs", dlls.len());
        }
        OutputFormat::Json => {
            for d in dlls {
                let json = serde_json::json!({
                    "name": d.name,
                    "base_addr": format!("{:#x}", d.base_addr),
                    "size": d.size,
                    "load_order": d.load_order,
                    "path": d.full_path,
                });
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
        }
        OutputFormat::Csv => {
            println!("name,base_addr,size,load_order,path");
            for d in dlls {
                let escaped = d.full_path.replace('"', "\"\"");
                println!(
                    "{},{:#x},{},{},\"{}\"",
                    d.name, d.base_addr, d.size, d.load_order, escaped
                );
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
            false,
            None,
            false,
            false,
            false,
        );
        // May succeed or fail with a walker error, but NOT with old CR3 bail
        if let Err(e) = &result {
            let msg = format!("{e}");
            assert!(!msg.contains("CR3 auto-detection"), "got old bail: {msg}");
        }
        std::fs::remove_file(&dump_path).ok();
        std::fs::remove_file(&isf_path).ok();
    }

    #[test]
    fn cmd_mod_with_lime_dump_attempts_analysis() {
        let dump_path = make_temp_lime_dump("modules");
        let isf_path = make_temp_isf_file("modules");
        let result = cmd_mod(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
            false,
            false,
            false,
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
    fn cmd_net_with_lime_dump_attempts_analysis() {
        let dump_path = make_temp_lime_dump("netstat");
        let isf_path = make_temp_isf_file("netstat");
        let result = cmd_net(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
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

    // --- New walker CLI subcommand tests ---

    #[test]
    fn cmd_maps_with_lime_dump_attempts_analysis() {
        let dump_path = make_temp_lime_dump("maps");
        let isf_path = make_temp_isf_file("maps");
        let result = cmd_maps(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
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
    fn cmd_files_with_lime_dump_attempts_analysis() {
        let dump_path = make_temp_lime_dump("files");
        let isf_path = make_temp_isf_file("files");
        let result = cmd_files(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
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
    fn cmd_envvars_with_lime_dump_attempts_analysis() {
        let dump_path = make_temp_lime_dump("envvars");
        let isf_path = make_temp_isf_file("envvars");
        let result = cmd_envvars(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
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
    fn cmd_malfind_with_lime_dump_attempts_analysis() {
        let dump_path = make_temp_lime_dump("malfind");
        let isf_path = make_temp_isf_file("malfind");
        let result = cmd_malfind(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
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
    fn cmd_mounts_with_lime_dump_attempts_analysis() {
        let dump_path = make_temp_lime_dump("mounts");
        let isf_path = make_temp_isf_file("mounts");
        let result = cmd_mounts(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
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
    fn cmd_mod_check_syscalls_with_lime_dump_attempts_analysis() {
        let dump_path = make_temp_lime_dump("syscalls");
        let isf_path = make_temp_isf_file("syscalls");
        let result = cmd_mod(
            &dump_path,
            Some(&isf_path),
            OutputFormat::Table,
            None,
            true,
            false,
            false,
            false,
        );
        if let Err(e) = &result {
            let msg = format!("{e}");
            assert!(!msg.contains("CR3 auto-detection"), "got old bail: {msg}");
        }
        std::fs::remove_file(&dump_path).ok();
        std::fs::remove_file(&isf_path).ok();
    }
}
