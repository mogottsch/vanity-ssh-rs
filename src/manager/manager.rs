use indicatif::{ProgressBar, ProgressStyle};
use num_format::{Locale, ToFormattedString};
use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use crate::cli::Args;
use crate::core::file_io::save_keypair_to_files;
use crate::core::keypair::KeyPair;
use crate::core::pattern::Pattern;
use crate::worker::message::WorkerMessage;

use super::ntfy::notify;

const RATE_WINDOW: Duration = Duration::from_secs(1);

struct ManagerState {
    total_attempts: u64,
    pattern_key_pairs: HashMap<Pattern, Vec<KeyPair>>,
    progress_bar: ProgressBar,
    attempt_history: VecDeque<(Instant, u64)>,
    attempt_history_total: u64,
}

impl ManagerState {
    fn new() -> Self {
        let progress_bar = ProgressBar::new_spinner();
        progress_bar.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}]\n{msg}")
                .unwrap(),
        );
        progress_bar.enable_steady_tick(Duration::from_millis(100));

        Self {
            total_attempts: 0,
            pattern_key_pairs: HashMap::new(),
            progress_bar,
            attempt_history: VecDeque::new(),
            attempt_history_total: 0,
        }
    }

    fn update_attempts(&mut self, attempts: u64, timestamp: Instant) {
        self.total_attempts += attempts;
        self.attempt_history.push_back((timestamp, attempts));
        self.attempt_history_total += attempts;
        self.prune_attempt_history(timestamp);
    }

    fn add_key_pair(&mut self, pattern: Pattern, key_pair: KeyPair) {
        self.pattern_key_pairs
            .entry(pattern)
            .or_default()
            .push(key_pair);
    }

    fn get_pattern_hits(&self, pattern: &Pattern) -> usize {
        self.pattern_key_pairs
            .get(pattern)
            .map_or(0, |keys| keys.len())
    }
}
pub fn run_manager(rx: Receiver<WorkerMessage>, start: Instant, patterns: &[Pattern], args: &Args) {
    let mut state = ManagerState::new();

    loop {
        if let Ok(msg) = rx.recv() {
            let now = Instant::now();
            state.update_attempts(msg.attempts, now);
            state
                .progress_bar
                .set_message(update_progress_message(&state, patterns, start));

            if let Some(search_hit) = msg.search_hit {
                if let Err(e) =
                    handle_search_hit(&mut state, search_hit.pattern, search_hit.key_pair, args)
                {
                    state
                        .progress_bar
                        .println(format!("Error handling search hit: {}", e));
                }

                if args.stop_after_match {
                    state.progress_bar.finish_and_clear();
                    break;
                }
            }
        }
    }
}

fn update_progress_message(state: &ManagerState, patterns: &[Pattern], start: Instant) -> String {
    let duration = start.elapsed();
    let elapsed_secs = duration.as_secs_f64();
    let avg_rate = if elapsed_secs > 0.0 {
        (state.total_attempts as f64 / elapsed_secs).round() as u64
    } else {
        0
    };
    let current_rate = state.rolling_rate();

    let mut progress_msg = format!(
        "Attempts: {} | {} keys/sec (1s) | {} keys/sec (avg)",
        state.total_attempts.to_formatted_string(&Locale::en),
        current_rate.to_formatted_string(&Locale::en),
        avg_rate.to_formatted_string(&Locale::en)
    );

    for pattern in patterns {
        progress_msg = format!(
            "{}\n{}",
            progress_msg,
            format_pattern_stats(pattern, avg_rate as f64)
        );

        let n_hits = state.get_pattern_hits(pattern);
        if n_hits > 0 {
            progress_msg = format!("{} | {}", progress_msg, format_hits_message(n_hits));
        }
    }

    progress_msg
}

impl ManagerState {
    fn prune_attempt_history(&mut self, timestamp: Instant) {
        while let Some(&(time, attempts)) = self.attempt_history.front() {
            if timestamp.duration_since(time) > RATE_WINDOW {
                self.attempt_history.pop_front();
                self.attempt_history_total -= attempts;
            } else {
                break;
            }
        }
    }

    fn rolling_rate(&self) -> u64 {
        if self.attempt_history.is_empty() {
            0
        } else {
            (self.attempt_history_total as f64 / RATE_WINDOW.as_secs_f64()).round() as u64
        }
    }
}

fn format_pattern_stats(pattern: &Pattern, rate: f64) -> String {
    let pattern_str = match pattern {
        Pattern::Suffix(s) => s.as_str(),
        Pattern::Regex(r) => r.as_str(),
    };

    match pattern.probability() {
        Some(prob) => {
            let expected_attempts = (1.0 / prob) as u64;
            let est_time = pattern
                .estimate_time(rate)
                .unwrap_or_default()
                .split_whitespace()
                .take(2)
                .collect::<Vec<_>>()
                .join(" ");

            format!(
                "Pattern '{}': 1 in {} (est. {})",
                pattern_str,
                expected_attempts.to_formatted_string(&Locale::en),
                est_time
            )
        }
        None => format!("Pattern '{}': regex pattern (no estimate)", pattern_str),
    }
}

fn format_hits_message(n_hits: usize) -> String {
    let is_plural = if n_hits == 1 { "" } else { "s" };
    format!(
        "{} key{} found",
        n_hits.to_formatted_string(&Locale::en),
        is_plural
    )
}

fn handle_search_hit(
    state: &mut ManagerState,
    pattern: Pattern,
    key_pair: KeyPair,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    state.add_key_pair(pattern.clone(), key_pair.clone());

    let filename = pattern.to_filename();
    state
        .progress_bar
        .println(format!("✨ Found matching key for pattern '{}'", pattern));

    save_keypair_to_files(&key_pair, &filename)?;
    state
        .progress_bar
        .println(format!("Key saved to 'out/{}'", filename));

    if let Some(topic) = &args.ntfy {
        notify(topic, &format!("Found key matching pattern '{}'", pattern))?;
    }

    Ok(())
}
