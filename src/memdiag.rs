#[cfg(target_os = "linux")]
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Default)]
pub struct MemSample {
    pub rss_kb: Option<u64>,
    pub cg_kb: Option<u64>,
    pub cg_anon_kb: Option<u64>,
    pub cg_file_kb: Option<u64>,
    pub cg_shmem_kb: Option<u64>,
    pub cg_file_mapped_kb: Option<u64>,
    pub cg_inactive_file_kb: Option<u64>,
    pub cg_active_file_kb: Option<u64>,
    pub cg_pgfault: Option<u64>,
    pub cg_pgmajfault: Option<u64>,
    pub cg_workingset_refault_file: Option<u64>,
    pub cg_workingset_activate_file: Option<u64>,
}

impl MemSample {
    pub fn rss_minus_cg_kb(&self) -> Option<i64> {
        Some(self.rss_kb? as i64 - self.cg_kb? as i64)
    }

    pub fn fmt_rss(&self) -> String {
        format_optional_u64(self.rss_kb)
    }

    pub fn fmt_cg(&self) -> String {
        format_optional_u64(self.cg_kb)
    }

    pub fn fmt_gap(&self) -> String {
        format_optional_i64(self.rss_minus_cg_kb())
    }

    pub fn fmt_anon(&self) -> String {
        format_optional_u64(self.cg_anon_kb)
    }

    pub fn fmt_file(&self) -> String {
        format_optional_u64(self.cg_file_kb)
    }

    pub fn fmt_shmem(&self) -> String {
        format_optional_u64(self.cg_shmem_kb)
    }

    pub fn fmt_file_mapped(&self) -> String {
        format_optional_u64(self.cg_file_mapped_kb)
    }

    pub fn fmt_inactive_file(&self) -> String {
        format_optional_u64(self.cg_inactive_file_kb)
    }

    pub fn fmt_active_file(&self) -> String {
        format_optional_u64(self.cg_active_file_kb)
    }

    pub fn fmt_pgfault(&self) -> String {
        format_optional_u64(self.cg_pgfault)
    }

    pub fn fmt_pgmajfault(&self) -> String {
        format_optional_u64(self.cg_pgmajfault)
    }

    pub fn fmt_workingset_refault_file(&self) -> String {
        format_optional_u64(self.cg_workingset_refault_file)
    }

    pub fn fmt_workingset_activate_file(&self) -> String {
        format_optional_u64(self.cg_workingset_activate_file)
    }
}

pub fn sample() -> MemSample {
    MemSample {
        rss_kb: process_rss_kb(),
        cg_kb: cgroup_memory_current_kb(),
        ..MemSample::default()
    }
}

pub fn sample_full() -> MemSample {
    #[cfg(target_os = "linux")]
    {
        let stat_map = cgroup_memory_stat_map();
        return MemSample {
            rss_kb: process_rss_kb(),
            cg_kb: cgroup_memory_current_kb(),
            cg_anon_kb: stat_value_kb(stat_map.as_ref(), &["anon", "rss", "total_rss"]),
            cg_file_kb: stat_value_kb(stat_map.as_ref(), &["file", "cache", "total_cache"]),
            cg_shmem_kb: stat_value_kb(stat_map.as_ref(), &["shmem", "total_shmem"]),
            cg_file_mapped_kb: stat_value_kb(
                stat_map.as_ref(),
                &["file_mapped", "mapped_file", "total_mapped_file"],
            ),
            cg_inactive_file_kb: stat_value_kb(
                stat_map.as_ref(),
                &["inactive_file", "total_inactive_file"],
            ),
            cg_active_file_kb: stat_value_kb(
                stat_map.as_ref(),
                &["active_file", "total_active_file"],
            ),
            cg_pgfault: stat_counter(stat_map.as_ref(), &["pgfault", "total_pgfault"]),
            cg_pgmajfault: stat_counter(stat_map.as_ref(), &["pgmajfault", "total_pgmajfault"]),
            cg_workingset_refault_file: stat_counter(
                stat_map.as_ref(),
                &["workingset_refault_file", "total_workingset_refault_file"],
            ),
            cg_workingset_activate_file: stat_counter(
                stat_map.as_ref(),
                &["workingset_activate_file", "total_workingset_activate_file"],
            ),
        };
    }
    #[cfg(not(target_os = "linux"))]
    {
        sample()
    }
}

pub fn counter_delta(before: Option<u64>, after: Option<u64>) -> Option<u64> {
    Some(after?.checked_sub(before?)?)
}

pub fn format_optional_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "na".to_string())
}

pub fn format_optional_i64(value: Option<i64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "na".to_string())
}

fn process_rss_kb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        parse_linux_proc_status_rss_kb(&status)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn parse_linux_proc_status_rss_kb(status: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let value = line.strip_prefix("VmRSS:")?.trim();
        value.split_whitespace().next()?.parse::<u64>().ok()
    })
}

fn cgroup_memory_current_kb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/sys/fs/cgroup/memory.current") {
            if let Ok(bytes) = s.trim().parse::<u64>() {
                return Some(bytes / 1024);
            }
        }
        if let Ok(s) = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.usage_in_bytes") {
            if let Ok(bytes) = s.trim().parse::<u64>() {
                return Some(bytes / 1024);
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn cgroup_memory_stat_map() -> Option<HashMap<String, u64>> {
    if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/memory.stat") {
        return Some(parse_cgroup_stat_map(&content));
    }
    if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.stat") {
        return Some(parse_cgroup_stat_map(&content));
    }
    None
}

#[cfg(target_os = "linux")]
fn parse_cgroup_stat_map(content: &str) -> HashMap<String, u64> {
    let mut values = HashMap::new();
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let Some(value) = parts.next() else {
            continue;
        };
        let Ok(value) = value.parse::<u64>() else {
            continue;
        };
        values.insert(key.to_string(), value);
    }
    values
}

#[cfg(target_os = "linux")]
fn stat_value_kb(stat_map: Option<&HashMap<String, u64>>, aliases: &[&str]) -> Option<u64> {
    let value = aliases
        .iter()
        .find_map(|key| stat_map.and_then(|map| map.get(*key)).copied())?;
    Some(value / 1024)
}

#[cfg(target_os = "linux")]
fn stat_counter(stat_map: Option<&HashMap<String, u64>>, aliases: &[&str]) -> Option<u64> {
    aliases
        .iter()
        .find_map(|key| stat_map.and_then(|map| map.get(*key)).copied())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_proc_status_rss() {
        let rss = parse_linux_proc_status_rss_kb(
            "Name:\ttoken-refresh\nState:\tS (sleeping)\nVmRSS:\t   14336 kB\nThreads:\t7\n",
        );

        assert_eq!(rss, Some(14336));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_cgroup_v2_memory_stat_fields() {
        let stat_map = parse_cgroup_stat_map(
            "anon 5722112\nfile 5283840\nshmem 131072\nfile_mapped 4128768\ninactive_file 4014080\nactive_file 1130496\npgfault 12345\npgmajfault 67\nworkingset_refault_file 89\nworkingset_activate_file 21\n",
        );

        assert_eq!(stat_value_kb(Some(&stat_map), &["anon"]), Some(5588));
        assert_eq!(stat_value_kb(Some(&stat_map), &["file"]), Some(5160));
        assert_eq!(stat_value_kb(Some(&stat_map), &["shmem"]), Some(128));
        assert_eq!(stat_value_kb(Some(&stat_map), &["file_mapped"]), Some(4032));
        assert_eq!(
            stat_value_kb(Some(&stat_map), &["inactive_file"]),
            Some(3920)
        );
        assert_eq!(stat_value_kb(Some(&stat_map), &["active_file"]), Some(1104));
        assert_eq!(stat_counter(Some(&stat_map), &["pgfault"]), Some(12345));
        assert_eq!(stat_counter(Some(&stat_map), &["pgmajfault"]), Some(67));
        assert_eq!(
            stat_counter(Some(&stat_map), &["workingset_refault_file"]),
            Some(89)
        );
        assert_eq!(
            stat_counter(Some(&stat_map), &["workingset_activate_file"]),
            Some(21)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_cgroup_v1_memory_stat_aliases() {
        let stat_map = parse_cgroup_stat_map(
            "rss 4587520\ncache 655360\nshmem 0\nmapped_file 327680\ninactive_file 262144\nactive_file 131072\ntotal_pgfault 900\ntotal_pgmajfault 3\n",
        );

        assert_eq!(
            stat_value_kb(Some(&stat_map), &["anon", "rss", "total_rss"]),
            Some(4480)
        );
        assert_eq!(
            stat_value_kb(Some(&stat_map), &["file", "cache", "total_cache"]),
            Some(640)
        );
        assert_eq!(
            stat_value_kb(
                Some(&stat_map),
                &["file_mapped", "mapped_file", "total_mapped_file"]
            ),
            Some(320)
        );
        assert_eq!(
            stat_counter(Some(&stat_map), &["pgfault", "total_pgfault"]),
            Some(900)
        );
        assert_eq!(
            stat_counter(Some(&stat_map), &["pgmajfault", "total_pgmajfault"]),
            Some(3)
        );
    }

    #[test]
    fn computes_counter_delta() {
        assert_eq!(counter_delta(Some(10), Some(42)), Some(32));
        assert_eq!(counter_delta(Some(10), None), None);
    }
}
