#![allow(dead_code)]

use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ScanMetrics {
	pub scanner_type: String,
	pub start_time: Instant,
	pub end_time: Option<Instant>,
	pub findings_count: usize,
	pub requests_sent: usize,
	pub errors_count: usize,
}

pub struct PerfProfiler {
	metrics: Vec<ScanMetrics>,
	total_start: Instant,
}

#[derive(Debug)]
pub struct PerfSummary {
	pub total_duration: Duration,
	pub total_findings: usize,
	pub total_requests: usize,
	pub total_errors: usize,
	pub scanners: Vec<ScannerPerf>,
	pub slowest_scanner: Option<String>,
	pub fastest_scanner: Option<String>,
	pub suggestions: Vec<String>,
}

#[derive(Debug)]
pub struct ScannerPerf {
	pub name: String,
	pub duration: Duration,
	pub findings: usize,
	pub requests: usize,
	pub findings_per_sec: f64,
}

impl ScanMetrics {
	pub fn new(scanner_type: &str) -> Self {
		Self {
			scanner_type: scanner_type.to_string(),
			start_time: Instant::now(),
			end_time: None,
			findings_count: 0,
			requests_sent: 0,
			errors_count: 0,
		}
	}

	pub fn duration(&self) -> Duration {
		match self.end_time {
			Some(end) => end.duration_since(self.start_time),
			None => self.start_time.elapsed(),
		}
	}

	pub fn findings_per_second(&self) -> f64 {
		let dur = self.duration().as_secs_f64();
		if dur == 0.0 {
			return 0.0;
		}
		self.findings_count as f64 / dur
	}

	pub fn finalize(&mut self) {
		self.end_time = Some(Instant::now());
	}
}

impl PerfProfiler {
	pub fn new() -> Self {
		Self {
			metrics: Vec::new(),
			total_start: Instant::now(),
		}
	}

	pub fn start_scanner(&mut self, scanner_type: &str) -> usize {
		self.metrics.push(ScanMetrics::new(scanner_type));
		self.metrics.len() - 1
	}

	pub fn end_scanner(
		&mut self,
		index: usize,
		findings: usize,
		requests: usize,
		errors: usize,
	) {
		if let Some(m) = self.metrics.get_mut(index) {
			m.findings_count = findings;
			m.requests_sent = requests;
			m.errors_count = errors;
			m.finalize();
		}
	}

	pub fn total_duration(&self) -> Duration {
		self.total_start.elapsed()
	}

	pub fn summary(&self) -> PerfSummary {
		let mut scanners = Vec::new();
		let mut total_findings = 0;
		let mut total_requests = 0;
		let mut total_errors = 0;

		for m in &self.metrics {
			let fps = m.findings_per_second();
			scanners.push(ScannerPerf {
				name: m.scanner_type.clone(),
				duration: m.duration(),
				findings: m.findings_count,
				requests: m.requests_sent,
				findings_per_sec: fps,
			});
			total_findings += m.findings_count;
			total_requests += m.requests_sent;
			total_errors += m.errors_count;
		}

		let slowest = scanners
			.iter()
			.max_by(|a, b| a.duration.cmp(&b.duration))
			.map(|s| s.name.clone());
		let fastest = scanners
			.iter()
			.min_by(|a, b| a.duration.cmp(&b.duration))
			.map(|s| s.name.clone());

		let suggestions = self.generate_suggestions();

		PerfSummary {
			total_duration: self.total_duration(),
			total_findings,
			total_requests,
			total_errors,
			scanners,
			slowest_scanner: slowest,
			fastest_scanner: fastest,
			suggestions,
		}
	}

	fn generate_suggestions(&self) -> Vec<String> {
		let mut suggestions = Vec::new();

		for m in &self.metrics {
			let dur = m.duration().as_secs_f64();
			if dur > 30.0 {
				suggestions.push(format!(
					"Consider reducing concurrency or timeout for {}",
					m.scanner_type
				));
			}
			if m.findings_per_second() < 0.1 && m.requests_sent > 0 {
				suggestions.push(format!(
					"{} has low throughput, consider optimizing",
					m.scanner_type
				));
			}
			if m.requests_sent > 0 && m.errors_count > m.requests_sent / 2 {
				suggestions.push(format!(
					"{} has high error rate, check connectivity",
					m.scanner_type
				));
			}
		}

		if self.total_duration().as_secs_f64() > 300.0 {
			suggestions.push(
				"Total scan time exceeds 5 minutes, consider --checks for targeted scanning"
					.to_string(),
			);
		}

		suggestions
	}

	pub fn print_report(&self) {
		let summary = self.summary();

		println!("\n===== Performance Report =====");
		println!("Total Duration: {:.2}s", summary.total_duration.as_secs_f64());
		println!("Total Findings: {}", summary.total_findings);
		println!("Total Requests: {}", summary.total_requests);
		println!("Total Errors:   {}", summary.total_errors);

		if let Some(ref s) = summary.slowest_scanner {
			println!("Slowest Scanner: {}", s);
		}
		if let Some(ref f) = summary.fastest_scanner {
			println!("Fastest Scanner: {}", f);
		}

		println!("\n--- Per-Scanner Breakdown ---");
		for sp in &summary.scanners {
			println!(
				"  {} => {:.2}s, {} findings, {:.2} findings/s",
				sp.name, sp.duration.as_secs_f64(), sp.findings, sp.findings_per_sec
			);
		}

		if !summary.suggestions.is_empty() {
			println!("\n--- Optimization Suggestions ---");
			for s in &summary.suggestions {
				println!("  * {}", s);
			}
		}
		println!("=============================\n");
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_new_metrics() {
		let m = ScanMetrics::new("xss");
		assert_eq!(m.scanner_type, "xss");
		assert!(m.end_time.is_none());
		assert_eq!(m.findings_count, 0);
		assert_eq!(m.requests_sent, 0);
		assert_eq!(m.errors_count, 0);
	}

	#[test]
	fn test_metrics_duration() {
		let mut m = ScanMetrics::new("sqli");
		std::thread::sleep(Duration::from_millis(50));
		let d = m.duration();
		assert!(d.as_millis() >= 40);

		m.finalize();
		let d2 = m.duration();
		assert!(d2.as_millis() >= 40);
	}

	#[test]
	fn test_findings_per_second() {
		let mut m = ScanMetrics::new("headers");
		m.findings_count = 10;
		m.requests_sent = 100;
		m.errors_count = 0;
		m.end_time = Some(m.start_time + Duration::from_secs(2));
		assert!((m.findings_per_second() - 5.0).abs() < 0.01);
	}

	#[test]
	fn test_findings_per_second_zero_duration() {
		let m = ScanMetrics::new("fast");
		assert_eq!(m.findings_per_second(), 0.0);
	}

	#[test]
	fn test_new_profiler() {
		let p = PerfProfiler::new();
		assert!(p.metrics.is_empty());
	}

	#[test]
	fn test_start_end_scanner() {
		let mut p = PerfProfiler::new();
		let idx = p.start_scanner("xss");
		assert_eq!(idx, 0);
		p.end_scanner(idx, 5, 200, 2);

		let m = &p.metrics[0];
		assert_eq!(m.findings_count, 5);
		assert_eq!(m.requests_sent, 200);
		assert_eq!(m.errors_count, 2);
		assert!(m.end_time.is_some());
	}

	#[test]
	fn test_summary() {
		let mut p = PerfProfiler::new();
		let i1 = p.start_scanner("xss");
		p.end_scanner(i1, 10, 500, 5);
		let i2 = p.start_scanner("sqli");
		p.end_scanner(i2, 20, 1000, 10);

		let s = p.summary();
		assert_eq!(s.total_findings, 30);
		assert_eq!(s.total_requests, 1500);
		assert_eq!(s.total_errors, 15);
		assert_eq!(s.scanners.len(), 2);
		assert!(!s.scanners.is_empty());
	}

	#[test]
	fn test_suggestions_generation() {
		let mut p = PerfProfiler::new();

		let i1 = p.start_scanner("slow");
		p.metrics[0].end_time = Some(p.metrics[0].start_time + Duration::from_secs(35));
		p.metrics[0].findings_count = 0;
		p.metrics[0].requests_sent = 100;
		p.end_scanner(i1, 0, 100, 0);

		let i2 = p.start_scanner("error_heavy");
		p.end_scanner(i2, 1, 100, 90);

		let s = p.summary();
		assert!(s.suggestions.iter().any(|x| x.contains("slow")));
		assert!(s.suggestions.iter().any(|x| x.contains("error_heavy")));
	}

	#[test]
	fn test_print_report() {
		let mut p = PerfProfiler::new();
		let i1 = p.start_scanner("xss");
		p.end_scanner(i1, 5, 100, 0);
		let i2 = p.start_scanner("sqli");
		p.end_scanner(i2, 10, 200, 1);
		p.print_report();
	}
}
