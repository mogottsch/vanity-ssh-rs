use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread;

use crate::core::keypair::BATCH_SIZE;
use crate::core::pattern::Pattern;
use crate::worker::generator::generate_and_check_batch;
use crate::worker::message::WorkerMessage;

use super::message::SearchHit;

pub fn spawn_worker_threads(
    n_threads: usize,
    patterns: Arc<Vec<Pattern>>,
    tx: Sender<WorkerMessage>,
    stop_flag: Arc<AtomicBool>,
) -> Vec<thread::JoinHandle<()>> {
    (0..n_threads)
        .map(|_| {
            let tx = tx.clone();
            let patterns = Arc::clone(&patterns);
            let stop_flag = Arc::clone(&stop_flag);
            thread::spawn(move || run_worker_loop(patterns, tx, stop_flag))
        })
        .collect()
}

pub fn run_worker_loop(
    patterns: Arc<Vec<Pattern>>,
    tx: Sender<WorkerMessage>,
    stop_flag: Arc<AtomicBool>,
) {
    let mut local_attempts = 0;

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        let result = generate_and_check_batch(&patterns);
        local_attempts += BATCH_SIZE as u64;

        if let Some((key_pair, pattern)) = result {
            send_success(&tx, key_pair, local_attempts, pattern);
            break;
        }

        if local_attempts % 10000 == 0 {
            send_progress_update(&tx, local_attempts);
            local_attempts = 0;
        }
    }
}

pub fn send_success(
    tx: &Sender<WorkerMessage>,
    key_pair: crate::core::keypair::KeyPair,
    attempts: u64,
    pattern: Pattern,
) {
    tx.send(WorkerMessage {
        attempts,
        search_hit: Some(SearchHit {
            key_pair,
            pattern: pattern.clone(),
        }),
    })
    .unwrap();
}

pub fn send_progress_update(tx: &Sender<WorkerMessage>, attempts: u64) {
    tx.send(WorkerMessage {
        attempts,
        search_hit: None,
    })
    .unwrap();
}
