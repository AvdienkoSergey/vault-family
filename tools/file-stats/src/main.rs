use std::fs;
use std::path::{Path, PathBuf};

struct FileStats {
    path: String,
    total_lines: usize,
    prod_lines: usize,
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

    // Files named tests.rs are entirely test code (#[cfg(test)] mod tests; in parent)
    let is_test_file = path.file_name().is_some_and(|name| name == "tests.rs");

    let (prod_lines, test_lines) = if is_test_file {
        (0, total_lines)
    } else {
        count_prod_and_test(&lines)
    };

    let rel = path
        .strip_prefix(src_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");

    FileStats {
        path: rel,
        total_lines,
        prod_lines,
        test_lines,
    }
}

/// Returns (prod_code_lines, test_total_lines).
/// prod_code_lines = non-blank, non-comment lines OUTSIDE #[cfg(test)] blocks.
/// test_total_lines = ALL lines inside #[cfg(test)] blocks.
fn count_prod_and_test(lines: &[&str]) -> (usize, usize) {
    let in_test = mark_test_lines(lines);

    let prod_lines = lines
        .iter()
        .enumerate()
        .filter(|(i, l)| {
            let trimmed = l.trim();
            !in_test[*i] && !trimmed.is_empty() && !trimmed.starts_with("//")
        })
        .count();

    let test_lines = in_test.iter().filter(|&&b| b).count();

    (prod_lines, test_lines)
}

/// Returns a Vec<bool> marking which lines are inside #[cfg(test)] modules.
fn mark_test_lines(lines: &[&str]) -> Vec<bool> {
    let mut result = vec![false; lines.len()];
    let mut in_test_module = false;
    let mut brace_depth: i32 = 0;
    let mut cfg_test_seen = false;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        if !in_test_module {
            if trimmed.contains("#[cfg(test)]") {
                cfg_test_seen = true;
                result[i] = true;
                continue;
            }

            if cfg_test_seen {
                result[i] = true;
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
            result[i] = true;
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

    result
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
    let prod_all: usize = stats.iter().map(|s| s.prod_lines).sum();
    let test_all: usize = stats.iter().map(|s| s.test_lines).sum();

    // Header
    println!();
    println!(
        "  {:<max_path$}  {:>7}  {:>7}  {:>7}  {:>5}",
        "File", "Total", "Prod", "Tests", "T%",
        max_path = max_path
    );
    println!("  {}", "─".repeat(max_path + 32));

    for s in &stats {
        let test_pct = if s.total_lines > 0 {
            (s.test_lines as f64 / s.total_lines as f64 * 100.0) as usize
        } else {
            0
        };

        let marker = if is_candidate(s) { "!" } else { " " };

        println!(
            "{} {:<max_path$}  {:>7}  {:>7}  {:>7}  {:>4}%",
            marker,
            s.path,
            s.total_lines,
            s.prod_lines,
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
        prod_all,
        test_all,
        test_pct_all,
        max_path = max_path
    );
    println!();

    // Summary
    let candidates: Vec<&FileStats> = stats.iter().filter(|s| is_candidate(s)).collect();
    if !candidates.is_empty() {
        println!("  Candidates for splitting:");
        for f in &candidates {
            let reason = if f.prod_lines > 400 && f.prod_lines > 0 && f.test_lines > f.prod_lines * 2
            {
                format!("{} prod + {} test (large & test-heavy)", f.prod_lines, f.test_lines)
            } else if f.prod_lines > 400 {
                format!("{} prod (large file)", f.prod_lines)
            } else {
                format!(
                    "{} prod + {} test (test:prod > 2:1)",
                    f.prod_lines, f.test_lines
                )
            };
            println!("    ! {}  — {}", f.path, reason);
        }
        println!();
    }
}

/// Candidate if: prod > 400 lines OR (has prod code AND test:prod > 2:1)
fn is_candidate(s: &FileStats) -> bool {
    if s.prod_lines > 400 {
        return true;
    }
    if s.prod_lines > 0 && s.test_lines > s.prod_lines * 2 {
        return true;
    }
    false
}
