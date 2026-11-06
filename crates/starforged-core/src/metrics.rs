//! Prometheus text exposition (plan M5b D6): hand-written counters,
//! gauges, and one histogram. No dependency. Labels are bounded: only
//! request class, status bucket, git service/transport, job kind/outcome,
//! index kind, and rate-limit name ever appear — never user, repository,
//! or token identifiers.

use std::collections::HashMap;
use std::sync::Mutex;

/// Fixed histogram buckets for `starforged_http_request_duration_seconds`.
pub const DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

type Labels = Vec<(String, String)>;

/// Live SSH connections for `starforged_ssh_connections` (plan M5b D6).
/// The SSH server bumps it on connect and drops it on disconnect.
pub static SSH_CONNECTIONS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

#[derive(Debug, Default)]
struct Histogram {
    /// Per-bucket counts (cumulative on render), plus count and sum.
    buckets: Vec<u64>,
    count: u64,
    sum: f64,
}

#[derive(Debug, Default)]
pub struct Metrics {
    counters: Mutex<HashMap<(String, Labels), u64>>,
    histograms: Mutex<HashMap<Labels, Histogram>>,
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

fn format_labels(labels: &Labels) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", escape_label(v)))
        .collect();
    format!("{{{}}}", parts.join(","))
}

fn help(name: &str) -> &'static str {
    match name {
        "starforged_http_requests_total" => "HTTP requests by class and status bucket.",
        "starforged_git_rpc_total" => "Git RPCs by service and transport.",
        "starforged_jobs_processed_total" => "Background jobs by kind and outcome.",
        "starforged_session_upload_bytes_total" => "Session segment bytes accepted.",
        "starforged_rate_limited_total" => "Requests refused by a rate limit.",
        "starforged_http_request_duration_seconds" => "HTTP request duration in seconds.",
        "starforged_jobs_pending" => "Queued background jobs by kind.",
        "starforged_index_documents" => "Search index documents by kind.",
        "starforged_ssh_connections" => "Live SSH connections.",
        _ => "",
    }
}
impl Metrics {
    pub fn new() -> Metrics {
        Metrics::default()
    }

    fn inc(&self, name: &str, labels: Labels, by: u64) {
        let mut counters = self.counters.lock().unwrap();
        *counters.entry((name.to_owned(), labels)).or_insert(0) += by;
    }

    /// `starforged_http_requests_total{class, status}`.
    pub fn inc_http(&self, class: &str, status: u16) {
        let bucket = match status {
            200..300 => "2xx",
            300..400 => "3xx",
            400..500 => "4xx",
            _ => "5xx",
        };
        self.inc(
            "starforged_http_requests_total",
            vec![
                ("class".to_owned(), class.to_owned()),
                ("status".to_owned(), bucket.to_owned()),
            ],
            1,
        );
    }

    /// Observe one request duration into `starforged_http_request_duration_seconds{class}`.
    pub fn observe_http(&self, class: &str, secs: f64) {
        let mut histograms = self.histograms.lock().unwrap();
        let hist = histograms
            .entry(vec![("class".to_owned(), class.to_owned())])
            .or_insert_with(|| Histogram {
                buckets: vec![0; DURATION_BUCKETS.len()],
                count: 0,
                sum: 0.0,
            });
        // Only the first bucket >= the observation counts; `render`
        // prefix-sums into the cumulative `le` exposition.
        if let Some(i) = DURATION_BUCKETS.iter().position(|bucket| secs <= *bucket) {
            hist.buckets[i] += 1;
        }
        hist.count += 1;
        hist.sum += secs;
    }

    /// Records one request: counter bump and duration observation.
    pub fn record_http(&self, class: &str, status: u16, secs: f64) {
        self.inc_http(class, status);
        self.observe_http(class, secs);
    }

    /// `starforged_git_rpc_total{service, transport}`.
    pub fn inc_git_rpc(&self, service: &str, transport: &str) {
        self.inc(
            "starforged_git_rpc_total",
            vec![
                ("service".to_owned(), service.to_owned()),
                ("transport".to_owned(), transport.to_owned()),
            ],
            1,
        );
    }

    /// `starforged_jobs_processed_total{kind, outcome}`.
    pub fn inc_job(&self, kind: &str, outcome: &str) {
        self.inc(
            "starforged_jobs_processed_total",
            vec![
                ("kind".to_owned(), kind.to_owned()),
                ("outcome".to_owned(), outcome.to_owned()),
            ],
            1,
        );
    }

    /// `starforged_session_upload_bytes_total` (no labels).
    pub fn add_session_upload_bytes(&self, bytes: u64) {
        self.inc("starforged_session_upload_bytes_total", Vec::new(), bytes);
    }

    /// `starforged_rate_limited_total{limit}`.
    pub fn inc_rate_limited(&self, limit: &str) {
        self.inc(
            "starforged_rate_limited_total",
            vec![("limit".to_owned(), limit.to_owned())],
            1,
        );
    }

    /// Renders the full exposition. `gauges` carries the gauge values
    /// computed from the database and index by the caller:
    /// `starforged_jobs_pending{kind}`, `starforged_index_documents{kind}`,
    /// `starforged_ssh_connections`.
    pub fn render(&self, gauges: &[(String, Labels, i64)]) -> String {
        let mut out = String::new();
        // Counters, sorted for deterministic output.
        let counters = self.counters.lock().unwrap();
        let mut entries: Vec<_> = counters.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let mut last_name = "";
        for ((name, labels), value) in &entries {
            if name != last_name {
                out.push_str(&format!("# HELP {name} {}\n", help(name)));
                out.push_str(&format!("# TYPE {name} counter\n"));
                last_name = name;
            }
            out.push_str(&format!("{name}{} {value}\n", format_labels(labels)));
        }
        drop(counters);

        // Histogram.
        if !self.histograms.lock().unwrap().is_empty() {
            out.push_str("# HELP starforged_http_request_duration_seconds HTTP request duration in seconds.\n");
            out.push_str("# TYPE starforged_http_request_duration_seconds histogram\n");
            let histograms = self.histograms.lock().unwrap();
            let mut classes: Vec<_> = histograms.iter().collect();
            classes.sort_by(|a, b| a.0.cmp(b.0));
            for (labels, hist) in classes {
                let mut cumulative = 0u64;
                for (i, bucket) in DURATION_BUCKETS.iter().enumerate() {
                    cumulative += hist.buckets[i];
                    let mut le_labels = labels.clone();
                    le_labels.push(("le".to_owned(), format!("{bucket}")));
                    out.push_str(&format!(
                        "starforged_http_request_duration_seconds_bucket{} {cumulative}\n",
                        format_labels(&le_labels)
                    ));
                }
                let mut inf_labels = labels.clone();
                inf_labels.push(("le".to_owned(), "+Inf".to_owned()));
                out.push_str(&format!(
                    "starforged_http_request_duration_seconds_bucket{} {}\n",
                    format_labels(&inf_labels),
                    hist.count
                ));
                out.push_str(&format!(
                    "starforged_http_request_duration_seconds_sum{} {}\n",
                    format_labels(labels),
                    hist.sum
                ));
                out.push_str(&format!(
                    "starforged_http_request_duration_seconds_count{} {}\n",
                    format_labels(labels),
                    hist.count
                ));
            }
        }

        // Gauges.
        if !gauges.is_empty() {
            let mut sorted: Vec<_> = gauges.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
            let mut last_name = "";
            for (name, labels, value) in sorted {
                if name != last_name {
                    out.push_str(&format!("# HELP {name} {}\n", help(name)));
                    out.push_str(&format!("# TYPE {name} gauge\n"));
                    last_name = name;
                }
                out.push_str(&format!("{name}{} {value}\n", format_labels(labels)));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposition_format_and_histogram() {
        let m = Metrics::new();
        m.inc_http("web", 200);
        m.inc_http("web", 404);
        // One observation per bucket boundary: 0.003 lands in 0.005,
        // 0.03 in 0.05, 0.4 in 0.5, 3.0 in 5.0, 20.0 beyond 10.0.
        for secs in [0.003, 0.03, 0.4, 3.0, 20.0] {
            m.observe_http("web", secs);
        }
        m.inc_git_rpc("upload-pack", "http");
        m.inc_job("hourly_cleanup", "ok");
        m.add_session_upload_bytes(42);
        m.inc_rate_limited("api");
        let text = m.render(&[("starforged_ssh_connections".to_owned(), Vec::new(), 3)]);
        assert!(text.contains("starforged_http_requests_total{class=\"web\",status=\"2xx\"} 1\n"));
        assert!(text.contains("starforged_http_requests_total{class=\"web\",status=\"4xx\"} 1\n"));
        assert!(
            text.contains(
                "starforged_git_rpc_total{service=\"upload-pack\",transport=\"http\"} 1\n"
            )
        );
        assert!(text.contains(
            "starforged_jobs_processed_total{kind=\"hourly_cleanup\",outcome=\"ok\"} 1\n"
        ));
        assert!(text.contains("starforged_session_upload_bytes_total 42\n"));
        assert!(text.contains("starforged_rate_limited_total{limit=\"api\"} 1\n"));
        // Cumulative `le` expectations (single accumulation + prefix sum):
        // every finite bucket tops out at 4 (the 20 s observation is only
        // in +Inf), so no bucket exceeds the observation count of 5.
        let expected = [
            ("0.005", 1),
            ("0.01", 1),
            ("0.025", 1),
            ("0.05", 2),
            ("0.1", 2),
            ("0.25", 2),
            ("0.5", 3),
            ("1", 3),
            ("2.5", 3),
            ("5", 4),
            ("10", 4),
            ("+Inf", 5),
        ];
        for (le, cumulative) in expected {
            let line = format!(
                "starforged_http_request_duration_seconds_bucket{{class=\"web\",le=\"{le}\"}} {cumulative}\n"
            );
            assert!(text.contains(&line), "missing bucket line: {line}");
        }
        assert!(text.contains("starforged_http_request_duration_seconds_count{class=\"web\"} 5\n"));
        assert!(
            text.contains("starforged_http_request_duration_seconds_sum{class=\"web\"} 23.433\n")
        );
        assert!(text.contains("# HELP starforged_http_requests_total "));
        assert!(text.contains("# HELP starforged_http_request_duration_seconds "));
        assert!(text.contains("# HELP starforged_ssh_connections "));
        assert!(text.contains("starforged_ssh_connections 3\n"));
    }
}
