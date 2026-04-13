use std::{
    sync::atomic::{AtomicI64, Ordering},
    time::Duration,
};

/// Default overcommit ceiling (raw streams).
pub const DEFAULT_MAX_OVERCOMMIT_STREAMS: u64 = 100_000;

/// Default RTT above which a connection is considered "high risk".
pub const DEFAULT_HIGH_RTT_THRESHOLD: Duration = Duration::from_millis(50);

/// Default load fraction at which overcommit management activates.
pub const DEFAULT_OVERCOMMIT_ACTIVATION_LOAD: f64 = 0.5;

/// Tracks aggregate allocated streams for high-RTT connections.
///
/// Each connection with RTT above `high_rtt_threshold` reports its
/// last-applied `max_streams` value. The tracker maintains a running
/// sum so that [`pressure`] can be queried cheaply on the hot path.
pub struct OvercommitTracker {
    /// Sum of last-applied max_streams across all high-RTT connections.
    aggregate: AtomicI64,
    /// Maximum allowed aggregate before full reduction is applied.
    max_overcommit: u64,
    /// Connections with RTT below this are not tracked and never reduced.
    high_rtt_threshold: Duration,
    /// Load fraction (from LoadDebtTracker) at which reduction begins.
    activation_load: f64,
}

impl OvercommitTracker {
    pub fn new(max_overcommit: u64, high_rtt_threshold: Duration, activation_load: f64) -> Self {
        Self {
            aggregate: AtomicI64::new(0),
            max_overcommit,
            high_rtt_threshold,
            activation_load,
        }
    }

    /// Update the aggregate when a connection's applied max_streams changes.
    ///
    /// Called by the connection loop after `set_max_concurrent_uni_streams`,
    /// and by `remove_connection` with `new_streams = 0`.
    pub fn update(&self, old_streams: u32, new_streams: u32) {
        let delta = new_streams as i64 - old_streams as i64;
        if delta != 0 {
            self.aggregate.fetch_add(delta, Ordering::Relaxed);
        }
    }

    /// Fraction of the overcommit budget currently consumed.
    /// 0.0 = no overcommit, 1.0 = at ceiling, >1.0 = over ceiling.
    pub fn pressure(&self) -> f64 {
        let agg = self.aggregate.load(Ordering::Relaxed).max(0) as f64;
        agg / self.max_overcommit as f64
    }

    /// Raw aggregate (for stats / debugging).
    pub fn aggregate(&self) -> i64 {
        self.aggregate.load(Ordering::Relaxed)
    }

    pub fn high_rtt_threshold(&self) -> Duration {
        self.high_rtt_threshold
    }

    pub fn activation_load(&self) -> f64 {
        self.activation_load
    }

    /// Compute the reduction factor for a connection.
    ///
    /// Returns a value in `[0.0, 1.0]` where 0.0 means "no reduction" and
    /// 1.0 means "reduce to floor".
    ///
    /// Hysteresis: reduction activates at `risk_score >= 1.0` and only
    /// deactivates when `risk_score < RECOVERY_RISK_THRESHOLD` (0.5).
    /// This prevents oscillation when risk hovers near the boundary.
    ///
    /// Arguments:
    /// - `load_level`: continuous load from `LoadDebtTracker::load_level()`
    ///   (0.0 = idle, 1.0 = saturated, >1.0 = debt)
    /// - `connection_rtt`: this connection's cached RTT
    /// - `currently_reduced`: whether this connection is already under reduction
    ///
    /// Connections with RTT <= `high_rtt_threshold` should not call this
    /// (caller must gate on threshold).
    pub fn reduction_factor(
        &self,
        load_level: f64,
        connection_rtt: Duration,
        currently_reduced: bool,
    ) -> f64 {
        if load_level < self.activation_load {
            return 0.0;
        }

        // Map [activation, 1.0] to [0.0, 1.0], continues >1.0 into debt territory.
        let adjusted_load = (load_level - self.activation_load) / (1.0 - self.activation_load);

        let overcommit_pressure = self.pressure();

        let rtt_factor = connection_rtt.as_secs_f64() / self.high_rtt_threshold.as_secs_f64();

        let risk_score = adjusted_load * overcommit_pressure * rtt_factor;

        // Hysteresis: enter at risk >= 1.0, exit at risk < 0.5.
        const RECOVERY_THRESHOLD: f64 = 0.5;
        const ENTRY_THRESHOLD: f64 = 1.0;
        const MAX_RISK: f64 = 2.0;

        let threshold = if currently_reduced {
            RECOVERY_THRESHOLD
        } else {
            ENTRY_THRESHOLD
        };

        if risk_score < threshold {
            return 0.0;
        }

        // Ramp from 0 at threshold to 1.0 at MAX_RISK.
        // Entry (not reduced):   0 at risk=1.0, 1.0 at risk=2.0
        // Hysteresis (reduced):  0 at risk=0.5, 1.0 at risk=2.0
        ((risk_score - threshold) / (MAX_RISK - threshold)).clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker() -> OvercommitTracker {
        OvercommitTracker::new(1_000_000, Duration::from_millis(50), 0.5)
    }

    #[test]
    fn test_initial_state() {
        let t = tracker();
        assert_eq!(t.aggregate(), 0);
        assert_eq!(t.pressure(), 0.0);
    }

    #[test]
    fn test_update_increases_aggregate() {
        let t = tracker();
        t.update(0, 500);
        assert_eq!(t.aggregate(), 500);
        t.update(0, 300);
        assert_eq!(t.aggregate(), 800);
    }

    #[test]
    fn test_update_decreases_on_disconnect() {
        let t = tracker();
        t.update(0, 1000);
        t.update(1000, 0);
        assert_eq!(t.aggregate(), 0);
    }

    #[test]
    fn test_update_handles_quota_change() {
        let t = tracker();
        t.update(0, 500);
        t.update(500, 200);
        assert_eq!(t.aggregate(), 200);
    }

    #[test]
    fn test_pressure_at_ceiling() {
        let t = tracker();
        t.update(0, 1_000_000);
        assert!((t.pressure() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pressure_negative_aggregate_clamped() {
        let t = tracker();
        // Simulate double-disconnect or race — aggregate goes negative
        t.update(100, 0);
        assert_eq!(t.pressure(), 0.0);
    }

    // New formula: ((risk - 0.5) / 1.5).clamp(0, 1)
    // Enter at risk >= 1.0 (not currently reduced), stay until risk < 0.5 (currently reduced).

    #[test]
    fn test_no_reduction_below_activation_load() {
        let t = tracker();
        t.update(0, 1_000_000); // full overcommit
        let rtt = Duration::from_millis(200);
        // load_level = 0.4 < activation(0.5)
        assert_eq!(t.reduction_factor(0.4, rtt, false), 0.0);
        assert_eq!(t.reduction_factor(0.4, rtt, true), 0.0);
    }

    #[test]
    fn test_no_reduction_when_no_overcommit() {
        let t = tracker();
        // No streams registered → pressure = 0
        let rtt = Duration::from_millis(200);
        assert_eq!(t.reduction_factor(0.9, rtt, false), 0.0);
    }

    #[test]
    fn test_reduction_scales_with_rtt() {
        let t = tracker();
        t.update(0, 500_000); // pressure = 0.5
        let load = 1.0; // saturated → adjusted_load = 1.0

        // risk_score = 1.0 * 0.5 * rtt_factor
        // 50ms:  rtt_factor=1.0, risk=0.5 → not reduced: 0.0
        let r_50ms = t.reduction_factor(load, Duration::from_millis(50), false);
        assert_eq!(r_50ms, 0.0);

        // 100ms: rtt_factor=2.0, risk=1.0 → entry: (1.0-1.0)/1.0 = 0.0
        let r_100ms = t.reduction_factor(load, Duration::from_millis(100), false);
        assert_eq!(r_100ms, 0.0);

        // 200ms: rtt_factor=4.0, risk=2.0 → (2.0-1.0)/1.0 = 1.0
        let r_200ms = t.reduction_factor(load, Duration::from_millis(200), false);
        assert!((r_200ms - 1.0).abs() < f64::EPSILON, "got {r_200ms}");
    }

    #[test]
    fn test_graduated_reduction() {
        let t = tracker();
        t.update(0, 500_000); // pressure = 0.5
        let rtt = Duration::from_millis(150); // rtt_factor = 3.0
        // adjusted_load = (load - 0.5) / 0.5

        // load=0.75 → adjusted=0.5, risk=0.5*0.5*3.0=0.75 → not reduced: 0.0
        assert_eq!(t.reduction_factor(0.75, rtt, false), 0.0);

        // load=0.9 → adjusted=0.8, risk=0.8*0.5*3.0=1.2 → (1.2-1.0)/1.0 = 0.2
        let r = t.reduction_factor(0.9, rtt, false);
        assert!((r - 0.2).abs() < 0.01, "got {r}");

        // load=1.0 → adjusted=1.0, risk=1.0*0.5*3.0=1.5 → (1.5-1.0)/1.0 = 0.5
        let r = t.reduction_factor(1.0, rtt, false);
        assert!((r - 0.5).abs() < 0.01, "got {r}");
    }

    #[test]
    fn test_beyond_saturation_amplifies() {
        let t = tracker();
        t.update(0, 1_000_000); // pressure = 1.0
        let rtt = Duration::from_millis(100); // rtt_factor = 2.0
        // load=1.5 (debt) → adjusted=(1.5-0.5)/0.5=2.0
        // risk = 2.0 * 1.0 * 2.0 = 4.0 → (4.0-0.5)/1.5 = clamped to 1.0
        let r = t.reduction_factor(1.5, rtt, false);
        assert!((r - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_reduction_clamped_at_one() {
        let t = tracker();
        t.update(0, 1_000_000);
        // Extreme: load=2.0, rtt=200ms → should clamp at 1.0
        let r = t.reduction_factor(2.0, Duration::from_millis(200), false);
        assert!((r - 1.0).abs() < f64::EPSILON);
    }

    // -- Hysteresis --

    #[test]
    fn test_hysteresis_stays_reduced_above_recovery() {
        let t = tracker();
        t.update(0, 500_000); // pressure = 0.5
        // 100ms rtt_factor=2.0, load=0.85 → adjusted=0.7
        // risk = 0.7 * 0.5 * 2.0 = 0.7
        // Not reduced: 0.7 < 1.0 → 0.0
        assert_eq!(t.reduction_factor(0.85, Duration::from_millis(100), false), 0.0);
        // Currently reduced: 0.7 >= 0.5 → active, (0.7-0.5)/(2.0-0.5) = 0.133
        let r = t.reduction_factor(0.85, Duration::from_millis(100), true);
        assert!(r > 0.0, "should stay reduced in hysteresis band, got {r}");
        assert!((r - 0.133).abs() < 0.02, "got {r}");
    }

    #[test]
    fn test_hysteresis_exits_below_recovery() {
        let t = tracker();
        t.update(0, 500_000); // pressure = 0.5
        // 50ms rtt_factor=1.0, load=0.7 → adjusted=0.4
        // risk = 0.4 * 0.5 * 1.0 = 0.2 < 0.5 → exit
        assert_eq!(t.reduction_factor(0.7, Duration::from_millis(50), true), 0.0);
    }

    #[test]
    fn test_hysteresis_prevents_oscillation() {
        let t = tracker();
        t.update(0, 500_000); // pressure = 0.5
        let rtt = Duration::from_millis(150); // rtt_factor = 3.0

        // Step 1: load=1.0, adjusted=1.0, risk=1.0*0.5*3.0=1.5 → enters reduction
        let r = t.reduction_factor(1.0, rtt, false);
        assert!(r > 0.0, "should enter reduction at risk=1.5");

        // Step 2: load drops to 0.85, adjusted=0.7, risk=0.7*0.5*3.0=1.05
        // Without hysteresis: 1.05 > 1.0 → still in. But if it dropped to 0.9:
        // risk=0.6*0.5*3.0=0.9 → would exit without hysteresis.
        // With hysteresis: 0.9 >= 0.5 → stays reduced.
        let r = t.reduction_factor(0.8, rtt, true);
        // adjusted=0.6, risk=0.6*0.5*3.0=0.9 → (0.9-0.5)/1.5 = 0.267
        assert!(r > 0.0, "should stay reduced at risk=0.9 (hysteresis band)");

        // Step 3: load drops further → risk < 0.5 → exits
        // load=0.6 → adjusted=0.2, risk=0.2*0.5*3.0=0.3
        let r = t.reduction_factor(0.6, rtt, true);
        assert_eq!(r, 0.0, "should exit at risk=0.3");
    }
}
