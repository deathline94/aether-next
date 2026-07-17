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
            // Turbo: still fast, but sample a few successes and pick lowest RTT
            // (early_exit_first often locks a high-latency edge and kills speed).
            ScanMode::Turbo => HuntStrategy {
                concurrency: 24,
                // H3 handshakes often need >5s on high-RTT links.
                per_probe_timeout: Duration::from_millis(8000),
                overall_deadline: Duration::from_secs(50),
                quiet_after_first: Duration::from_secs(5),
                target_successes: 4,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 96,
            },
            ScanMode::Balanced => HuntStrategy {
                concurrency: 20,
                per_probe_timeout: Duration::from_millis(6000),
                overall_deadline: Duration::from_secs(120),
                quiet_after_first: Duration::from_secs(15),
                target_successes: 8,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 180,
            },
            ScanMode::Thorough => HuntStrategy {
                concurrency: 24,
                per_probe_timeout: Duration::from_millis(10000),
                overall_deadline: Duration::from_secs(300),
                quiet_after_first: Duration::from_secs(30),
                target_successes: 0,
                early_exit_first: false,
                full_subnet: true,
                sample_per_cidr: 0,
            },
            ScanMode::Stealth => HuntStrategy {
                concurrency: 4,
                per_probe_timeout: Duration::from_millis(12000),
                overall_deadline: Duration::from_secs(180),
                quiet_after_first: Duration::from_secs(25),
                target_successes: 4,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 80,
            },
        }
    }

    /// Strategy tuned for WireGuard (UDP handshake probes).
    /// Turbo must finish fast and always return — hung hunts are worse than a clean fail.
    pub fn wg_strategy(&self) -> HuntStrategy {
        match self {
            ScanMode::Turbo => HuntStrategy {
                concurrency: 20,
                per_probe_timeout: Duration::from_millis(3500),
                overall_deadline: Duration::from_secs(28),
                quiet_after_first: Duration::from_secs(0),
                target_successes: 1,
                early_exit_first: true,
                full_subnet: false,
                sample_per_cidr: 24,
            },
            ScanMode::Balanced => HuntStrategy {
                concurrency: 14,
                per_probe_timeout: Duration::from_millis(5000),
                overall_deadline: Duration::from_secs(55),
                quiet_after_first: Duration::from_secs(6),
                target_successes: 4,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 64,
            },
            ScanMode::Thorough => HuntStrategy {
                concurrency: 12,
                per_probe_timeout: Duration::from_millis(7000),
                overall_deadline: Duration::from_secs(120),
                quiet_after_first: Duration::from_secs(15),
                target_successes: 0,
                early_exit_first: false,
                full_subnet: true,
                sample_per_cidr: 0,
            },
            ScanMode::Stealth => HuntStrategy {
                concurrency: 3,
                per_probe_timeout: Duration::from_millis(8000),
                overall_deadline: Duration::from_secs(90),
                quiet_after_first: Duration::from_secs(12),
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
}
