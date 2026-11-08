//! Dispatch on demand: the coordinator starts worker runs (`workflow_dispatch`
//! with its `GITHUB_TOKEN`) only while actions are waiting for a slot, up to
//! a cap. Workers leave by themselves once idle, so nothing runs without
//! work to do.

use crate::cert::PublicKey;
use crate::worker::Pool;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const TICK: Duration = Duration::from_secs(5);
/// A dispatched worker that has not joined by then is assumed lost.
const JOIN_WITHIN: Duration = Duration::from_secs(300);
const PER_TICK: usize = 2;

pub struct Dispatcher {
    /// `owner/repo`
    pub repository: String,
    /// The workflow file to dispatch, e.g. `attested.yml`.
    pub workflow: String,
    /// The ref to dispatch on (this run's branch).
    pub git_ref: String,
    /// `GITHUB_TOKEN` with `actions: write`.
    pub token: String,
    pub coordinator: PublicKey,
    pub coordinator_run: String,
    pub max_workers: usize,
    /// Actions one worker runs at once, to size dispatches.
    pub worker_slots: usize,
}

#[derive(Debug, thiserror::Error)]
#[error("dispatch: {0}")]
pub struct DispatchError(String);

impl Dispatcher {
    async fn dispatch_one(&self) -> Result<(), DispatchError> {
        let url = format!(
            "https://api.github.com/repos/{}/actions/workflows/{}/dispatches",
            self.repository, self.workflow
        );
        let body = serde_json::json!({
            "ref": self.git_ref,
            "inputs": {
                "role": "worker",
                "coordinator": self.coordinator.to_string(),
                "coordinator_run": self.coordinator_run,
            },
        });
        let r = crate::http::client()
            .post(url)
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .json(&body)
            .send()
            .await
            .map_err(|e| DispatchError(e.to_string()))?;
        if r.status().is_success() {
            Ok(())
        } else {
            let status = r.status();
            Err(DispatchError(format!(
                "{status}: {}",
                r.text().await.unwrap_or_default()
            )))
        }
    }

    /// How many more workers to dispatch now.
    fn wanted(&self, queued: usize, members: usize, starting: usize) -> usize {
        let want = queued
            .div_ceil(self.worker_slots.max(1))
            .min(self.max_workers);
        want.saturating_sub(members + starting).min(PER_TICK)
    }

    /// Runs until the process ends.
    pub async fn run(self, pool: Arc<Pool>, queued: Arc<AtomicUsize>) {
        let mut starting: Vec<Instant> = Vec::new();
        let mut joined_seen = pool.joined();
        let mut tick = tokio::time::interval(TICK);
        loop {
            tick.tick().await;
            // Joins since the last tick account for the oldest dispatches.
            let joined = pool.joined();
            starting.drain(..(joined - joined_seen).min(starting.len()));
            joined_seen = joined;
            starting.retain(|t| t.elapsed() < JOIN_WITHIN);

            let n = self.wanted(
                queued.load(Ordering::Acquire),
                pool.members(),
                starting.len(),
            );
            for _ in 0..n {
                match self.dispatch_one().await {
                    Ok(()) => {
                        starting.push(Instant::now());
                        tracing::info!(
                            starting = starting.len(),
                            members = pool.members(),
                            "dispatched a worker"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "could not dispatch a worker");
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(max: usize) -> Dispatcher {
        Dispatcher {
            repository: "o/r".into(),
            workflow: "w.yml".into(),
            git_ref: "main".into(),
            token: String::new(),
            coordinator: PublicKey::from_bytes([0; 32]),
            coordinator_run: "1".into(),
            max_workers: max,
            worker_slots: 2,
        }
    }

    #[test]
    fn dispatches_only_for_waiting_work_and_within_the_cap() {
        let d = d(4);
        assert_eq!(d.wanted(0, 0, 0), 0, "no queue, no workers");
        assert_eq!(d.wanted(1, 0, 0), 1);
        assert_eq!(d.wanted(9, 0, 0), 2, "at most two per tick");
        assert_eq!(
            d.wanted(9, 2, 1),
            1,
            "five wanted, capped at four, three present"
        );
        assert_eq!(d.wanted(100, 4, 0), 0, "at the cap");
        assert_eq!(d.wanted(3, 1, 1), 0, "two wanted, two present or starting");
    }
}
