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
                concurrency: 48,
                per_probe_timeout: Duration::from_millis(6000),
                overall_deadline: Duration::from_secs(40),
                quiet_after_first: Duration::from_secs(3),
                target_successes: 3,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 80,
            },
            ScanMode::Balanced => HuntStrategy {
                concurrency: 40,
                per_probe_timeout: Duration::from_millis(5500),
                overall_deadline: Duration::from_secs(90),
                quiet_after_first: Duration::from_secs(8),
                target_successes: 6,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 160,
            },
            ScanMode::Thorough => HuntStrategy {
                concurrency: 36,
                per_probe_timeout: Duration::from_millis(9000),
                overall_deadline: Duration::from_secs(240),
                quiet_after_first: Duration::from_secs(20),
                target_successes: 0,
                early_exit_first: false,
                full_subnet: true,
                sample_per_cidr: 0,
            },
            ScanMode::Stealth => HuntStrategy {
                concurrency: 6,
                per_probe_timeout: Duration::from_millis(10000),
                overall_deadline: Duration::from_secs(160),
                quiet_after_first: Duration::from_secs(20),
                target_successes: 4,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 64,
            },
        }
    }

    /// Strategy tuned for WireGuard (UDP handshake probes).
    pub fn wg_strategy(&self) -> HuntStrategy {
        match self {
            ScanMode::Turbo => HuntStrategy {
                concurrency: 40,
                per_probe_timeout: Duration::from_millis(3000),
                overall_deadline: Duration::from_secs(24),
                quiet_after_first: Duration::from_secs(0),
                target_successes: 1,
                early_exit_first: true,
                full_subnet: false,
                sample_per_cidr: 24,
            },
            ScanMode::Balanced => HuntStrategy {
                concurrency: 28,
                per_probe_timeout: Duration::from_millis(4500),
                overall_deadline: Duration::from_secs(48),
                quiet_after_first: Duration::from_secs(4),
                target_successes: 4,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 64,
            },
            ScanMode::Thorough => HuntStrategy {
                concurrency: 24,
                per_probe_timeout: Duration::from_millis(6500),
                overall_deadline: Duration::from_secs(110),
                quiet_after_first: Duration::from_secs(12),
                target_successes: 0,
                early_exit_first: false,
                full_subnet: true,
                sample_per_cidr: 0,
            },
            ScanMode::Stealth => HuntStrategy {
                concurrency: 4,
                per_probe_timeout: Duration::from_millis(7500),
                overall_deadline: Duration::from_secs(80),
                quiet_after_first: Duration::from_secs(10),
                target_successes: 3,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 40,
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
