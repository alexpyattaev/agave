use {
    serde::{Deserialize, Serialize},
    std::sync::OnceLock,
    thread_priority::{NormalThreadSchedulePolicy, ThreadExt, ThreadSchedulePolicy},
};

static CORE_COUNT: OnceLock<usize> = OnceLock::new();

pub const DEFAULT_PRIORITY: u8 = 0;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub enum CoreAllocation {
    ///Use OS default allocation (i.e. do not alter core affinity)
    #[default]
    OsDefault,
    ///Pin each thread to a core in given range. Number of cores should be >= number of threads
    PinnedCores { min: usize, max: usize },
    ///Pin the threads to a set of cores
    DedicatedCoreSet { min: usize, max: usize },
}

impl CoreAllocation {
    /// Converts into a vector of core IDs. OsDefault is converted to empty vector.
    pub fn as_core_mask_vector(&self) -> Vec<usize> {
        let core_count = CORE_COUNT.get_or_init(num_cpus::get);
        match *self {
            CoreAllocation::PinnedCores { min, max } => (min..max).collect(),
            CoreAllocation::DedicatedCoreSet { min, max } => (min..max).collect(),
            CoreAllocation::OsDefault => Vec::from_iter(0..*core_count),
        }
    }
}

#[cfg(target_os = "linux")]
pub fn set_thread_affinity(cores: &[usize]) {
    assert!(
        !cores.is_empty(),
        "Can not call setaffinity with empty cores mask"
    );
    if let Err(e) = affinity::set_thread_affinity(cores) {
        let thread = std::thread::current();
        let msg = format!(
            "Can not set core affinity {:?} for thread {:?} named {:?}, error {e}",
            cores,
            thread.id(),
            thread.name()
        );
        panic!("{}", msg);
    }
}

#[cfg(not(target_os = "linux"))]
pub fn set_thread_affinity(_cores: &[usize]) {}

pub fn parse_policy(policy: &str) -> ThreadSchedulePolicy {
    match policy.to_uppercase().as_ref() {
        "BATCH" => ThreadSchedulePolicy::Normal(NormalThreadSchedulePolicy::Batch),
        "OTHER" => ThreadSchedulePolicy::Normal(NormalThreadSchedulePolicy::Other),
        "IDLE" => ThreadSchedulePolicy::Normal(NormalThreadSchedulePolicy::Idle),
        _ => panic!("Could not parse the policy"),
    }
}

///Applies policy to the calling thread
pub fn apply_policy(
    alloc: &CoreAllocation,
    policy: ThreadSchedulePolicy,
    priority: u8,
    chosen_cores_mask: &std::sync::Mutex<Vec<usize>>,
) {
    if let Err(e) = std::thread::current().set_priority_and_policy(
        policy,
        thread_priority::ThreadPriority::Crossplatform((priority).try_into().unwrap()),
    ) {
        panic!("Can not set thread priority, OS error {:?}", e);
    }

    match alloc {
        CoreAllocation::PinnedCores { min: _, max: _ } => {
            let mut lg = chosen_cores_mask
                .lock()
                .expect("Can not lock core mask mutex");
            let core = lg
                .pop()
                .expect("Not enough cores provided for pinned allocation");
            set_thread_affinity(&[core]);
        }
        CoreAllocation::DedicatedCoreSet { min: _, max: _ } => {
            let lg = chosen_cores_mask
                .lock()
                .expect("Can not lock core mask mutex");
            set_thread_affinity(&lg);
        }
        CoreAllocation::OsDefault => {}
    }
}
