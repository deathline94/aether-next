//! Shared scan mode + strategy knobs for MASQUE and WireGuard hunters.
use std::time::Duration;

/// Unified scan aggressiveness. Both hunters share this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Turbo,
    Balanced,
    Thorough,
    Stealth,
}

impl ScanMode {
    pub fn parse(s: &str) -> ScanMode {
        match s.trim().to_lowercase().as_str() {
            "turbo" | "fast" => ScanMode::Turbo,
            "thorough" | "deep" | "pro" => ScanMode::Thorough,
            "stealth" | "quiet" => ScanMode::Stealth,
            _ => ScanMode::Balanced,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ScanMode::Turbo => "turbo",
            ScanMode::Balanced => "balanced",
            ScanMode::Thorough => "thorough",
            ScanMode::Stealth => "stealth",
        }
    }

    /// Strategy tuned for MASQUE (TCP/QUIC probes).
    pub fn masque_strategy(&self) -> HuntStrategy {
        match self {
            // High concurrency + short quiet window for snappy connects.
            ScanMode::Turbo => HuntStrategy {
                concurrency: 64,
                per_probe_timeout: Duration::from_millis(1500),
                overall_deadline: Duration::from_secs(120),
                quiet_after_first: Duration::from_secs(0),
                target_successes: 1,
                early_exit_first: true, // Connect to absolute first one that works
                full_subnet: false,
                sample_per_cidr: 64,
                candidate_cap: 4500,
            },
            ScanMode::Balanced => HuntStrategy {
                concurrency: 40,
                per_probe_timeout: Duration::from_millis(4500),
                overall_deadline: Duration::from_secs(90),
                quiet_after_first: Duration::from_secs(5),
                target_successes: 4,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 160,
                candidate_cap: 3000,
            },
            ScanMode::Thorough => HuntStrategy {
                concurrency: 36,
                per_probe_timeout: Duration::from_millis(6000),
                overall_deadline: Duration::from_secs(240),
                quiet_after_first: Duration::from_secs(20),
                target_successes: 0,
                early_exit_first: false,
                full_subnet: true,
                sample_per_cidr: 0,
                candidate_cap: 10000,
            },
            ScanMode::Stealth => HuntStrategy {
                concurrency: 6,
                per_probe_timeout: Duration::from_millis(8000),
                overall_deadline: Duration::from_secs(160),
                quiet_after_first: Duration::from_secs(20),
                target_successes: 4,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 64,
                candidate_cap: 800,
            },
        }
    }

    /// Strategy tuned for WireGuard (UDP handshake probes).
    pub fn wg_strategy(&self) -> HuntStrategy {
        match self {
            ScanMode::Turbo => HuntStrategy {
                concurrency: 64,
                per_probe_timeout: Duration::from_millis(1500),
                overall_deadline: Duration::from_secs(120),
                quiet_after_first: Duration::from_secs(0),
                target_successes: 1,
                early_exit_first: true, // Connect to absolute first one that works
                full_subnet: false,
                sample_per_cidr: 64,
                candidate_cap: 4500,
            },
            ScanMode::Balanced => HuntStrategy {
                concurrency: 64,
                per_probe_timeout: Duration::from_millis(2000),
                overall_deadline: Duration::from_secs(120),
                quiet_after_first: Duration::from_secs(4),
                target_successes: 3,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 160,
                candidate_cap: 4500,
            },
            ScanMode::Thorough => HuntStrategy {
                concurrency: 40,
                per_probe_timeout: Duration::from_millis(3000),
                overall_deadline: Duration::from_secs(240),
                quiet_after_first: Duration::from_secs(12),
                target_successes: 0,
                early_exit_first: false,
                full_subnet: true,
                sample_per_cidr: 0,
                candidate_cap: 10000,
            },
            ScanMode::Stealth => HuntStrategy {
                concurrency: 8,
                per_probe_timeout: Duration::from_millis(4000),
                overall_deadline: Duration::from_secs(160),
                quiet_after_first: Duration::from_secs(10),
                target_successes: 3,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 64,
                candidate_cap: 1500,
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HuntStrategy {
    pub concurrency: usize,
    pub per_probe_timeout: Duration,
    pub overall_deadline: Duration,
    pub quiet_after_first: Duration,
    pub target_successes: usize,
    pub early_exit_first: bool,
    pub full_subnet: bool,
    pub sample_per_cidr: usize,
    pub candidate_cap: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_aliases() {
        assert_eq!(ScanMode::parse("fast"), ScanMode::Turbo);
        assert_eq!(ScanMode::parse("deep"), ScanMode::Thorough);
        assert_eq!(ScanMode::parse("quiet"), ScanMode::Stealth);
        assert_eq!(ScanMode::parse("nope"), ScanMode::Balanced);
    }

    #[test]
    fn strategies_differ_by_transport() {
        let m = ScanMode::Balanced;
        assert_ne!(m.masque_strategy().concurrency, m.wg_strategy().concurrency);
    }

    #[test]
    fn turbo_is_highly_concurrent() {
        assert!(ScanMode::Turbo.masque_strategy().concurrency >= 40);
        assert!(ScanMode::Balanced.masque_strategy().concurrency >= 32);
    }
}
