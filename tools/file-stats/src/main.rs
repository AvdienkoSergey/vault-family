use std::fs;
use std::path::{Path, PathBuf};

struct FileStats {
    path: String,
    total_lines: usize,
    code_lines: usize,
    test_lines: usize,
}

fn collect_rs_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, files);
        } else if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
}

fn count_lines(path: &Path, src_root: &Path) -> FileStats {
    let content = fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    let total_lines = lines.len();

    // Count non-blank, non-comment lines as code
    let code_lines = lines
        .iter()
        .filter(|l| {
            let trimmed = l.trim();
            !trimmed.is_empty() && !trimmed.starts_with("//")
        })
        .count();

    // Count lines inside #[cfg(test)] modules
    let test_lines = count_test_lines(&lines);

    let rel = path
        .strip_prefix(src_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");

    FileStats {
        path: rel,
        total_lines,
        code_lines,
        test_lines,
    }
}

/// Count lines that belong to `#[cfg(test)]` modules.
/// Tracks brace depth to find where the test module ends.
fn count_test_lines(lines: &[&str]) -> usize {
    let mut test_lines = 0;
    let mut in_test_module = false;
    let mut brace_depth: i32 = 0;
    let mut cfg_test_seen = false;

    for line in lines {
        let trimmed = line.trim();

        if !in_test_module {
            if trimmed.contains("#[cfg(test)]") {
                cfg_test_seen = true;
                test_lines += 1;
                continue;
            }

            if cfg_test_seen {
                test_lines += 1;
                // Look for opening brace of the mod
                if trimmed.contains('{') {
                    in_test_module = true;
                    brace_depth = 0;
                    for ch in trimmed.chars() {
                        match ch {
                            '{' => brace_depth += 1,
                            '}' => brace_depth -= 1,
                            _ => {}
                        }
                    }
                    if brace_depth <= 0 {
                        in_test_module = false;
                        cfg_test_seen = false;
                    }
                }
                continue;
            }
        } else {
            test_lines += 1;
            for ch in trimmed.chars() {
                match ch {
                    '{' => brace_depth += 1,
                    '}' => brace_depth -= 1,
                    _ => {}
                }
            }
            if brace_depth <= 0 {
                in_test_module = false;
                cfg_test_seen = false;
            }
        }
    }

    test_lines
}

fn main() {
    let src_dir = Path::new("src");
    if !src_dir.exists() {
        eprintln!("Error: run from project root (no src/ found)");
        std::process::exit(1);
    }

    let mut files = Vec::new();
    collect_rs_files(src_dir, &mut files);
    files.sort();

    let mut stats: Vec<FileStats> = files
        .iter()
        .map(|f| count_lines(f, Path::new("")))
        .collect();

    // Sort by total lines descending
    stats.sort_by(|a, b| b.total_lines.cmp(&a.total_lines));

    // Calculate column widths
    let max_path = stats
        .iter()
        .map(|s| s.path.len())
        .max()
        .unwrap_or(4)
        .max(4);

    let total_all: usize = stats.iter().map(|s| s.total_lines).sum();
    let code_all: usize = stats.iter().map(|s| s.code_lines).sum();
    let test_all: usize = stats.iter().map(|s| s.test_lines).sum();

    // Header
    println!();
    println!(
        "  {:<max_path$}  {:>7}  {:>7}  {:>7}  {:>5}",
        "File", "Total", "Code", "Tests", "T%",
        max_path = max_path
    );
    println!("  {}", "─".repeat(max_path + 32));

    for s in &stats {
        let test_pct = if s.total_lines > 0 {
            (s.test_lines as f64 / s.total_lines as f64 * 100.0) as usize
        } else {
            0
        };

        // Highlight large files (>300 lines)
        let marker = if s.total_lines > 300 { "!" } else { " " };

        println!(
            "{} {:<max_path$}  {:>7}  {:>7}  {:>7}  {:>4}%",
            marker,
            s.path,
            s.total_lines,
            s.code_lines,
            s.test_lines,
            test_pct,
            max_path = max_path
        );
    }

    println!("  {}", "─".repeat(max_path + 32));

    let test_pct_all = if total_all > 0 {
        (test_all as f64 / total_all as f64 * 100.0) as usize
    } else {
        0
    };

    println!(
        "  {:<max_path$}  {:>7}  {:>7}  {:>7}  {:>4}%",
        "TOTAL",
        total_all,
        code_all,
        test_all,
        test_pct_all,
        max_path = max_path
    );
    println!();

    // Summary
    let big_files: Vec<&FileStats> = stats.iter().filter(|s| s.total_lines > 300).collect();
    if !big_files.is_empty() {
        println!("  Candidates for splitting (>300 lines):");
        for f in &big_files {
            let prod_lines = f.total_lines - f.test_lines;
            println!(
                "    ! {}  — {} prod + {} test",
                f.path, prod_lines, f.test_lines
            );
        }
        println!();
    }
}
