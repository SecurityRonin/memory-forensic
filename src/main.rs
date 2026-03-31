#![deny(unsafe_code)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use comfy_table::{presets::UTF8_FULL_CONDENSED, Table};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "memf", about = "Memory forensics toolkit", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show dump format, physical ranges, and basic metadata.
    Info {
        /// Path to the memory dump file.
        dump: PathBuf,
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

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Info { dump } => cmd_info(&dump),
        Commands::Strings {
            dump,
            from_file,
            min_length,
            output,
            rules,
        } => cmd_strings(dump, from_file, min_length, output, rules),
    }
}

#[allow(clippy::cast_precision_loss)]
fn cmd_info(dump: &Path) -> Result<()> {
    let provider = memf_format::open_dump(dump)
        .with_context(|| format!("failed to open {}", dump.display()))?;

    println!("Format:     {}", provider.format_name());
    println!(
        "Total size: {} bytes ({:.2} GB)",
        provider.total_size(),
        provider.total_size() as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    println!("Ranges:     {}", provider.ranges().len());
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

fn cmd_strings(
    dump: Option<PathBuf>,
    from_file: Option<PathBuf>,
    min_length: usize,
    output: OutputFormat,
    rules: Option<PathBuf>,
) -> Result<()> {
    // Load strings from either a dump or a pre-extracted file
    let mut strings = if let Some(path) = from_file {
        memf_strings::from_file::from_strings_file(&path)
            .with_context(|| format!("failed to read strings file {}", path.display()))?
    } else if let Some(dump_path) = dump {
        let provider = memf_format::open_dump(&dump_path)
            .with_context(|| format!("failed to open {}", dump_path.display()))?;
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
