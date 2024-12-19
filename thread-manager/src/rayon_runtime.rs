use {
    crate::policy::{apply_policy, parse_policy, CoreAllocation},
    anyhow::Ok,
    serde::{Deserialize, Serialize},
    solana_metrics::datapoint_info,
    std::{
        ops::Deref,
        sync::{
            atomic::{AtomicI64, Ordering},
            Arc, Mutex,
        },
    },
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct RayonConfig {
    pub worker_threads: usize,
    /// Priority in range 1..99
    pub priority: u8,
    pub policy: String,
    pub stack_size_bytes: usize,
    pub core_allocation: CoreAllocation,
}

impl Default for RayonConfig {
    fn default() -> Self {
        Self {
            core_allocation: CoreAllocation::OsDefault,
            worker_threads: 16,
            priority: crate::policy::DEFAULT_PRIORITY,
            policy: "BATCH".to_owned(),
            stack_size_bytes: 2 * 1024 * 1024,
        }
    }
}

#[derive(Debug)]
pub struct RayonRuntimeInner {
    pub rayon_pool: rayon::ThreadPool,
    pub config: RayonConfig,
}
impl Deref for RayonRuntimeInner {
    type Target = rayon::ThreadPool;

    fn deref(&self) -> &Self::Target {
        &self.rayon_pool
    }
}

#[derive(Debug, Clone)]
pub struct RayonRuntime {
    inner: Arc<RayonRuntimeInner>,
}

impl Deref for RayonRuntime {
    type Target = RayonRuntimeInner;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl RayonRuntime {
    pub fn new(name: String, config: RayonConfig) -> anyhow::Result<Self> {
        let core_allocation = config.core_allocation.clone();
        let chosen_cores_mask = Mutex::new(core_allocation.as_core_mask_vector());
        let priority = config.priority;
        let policy = parse_policy(&config.policy);
        let spawned_threads = AtomicI64::new(0);
        let rayon_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(config.worker_threads)
            .thread_name(move |i| format!("{}_{}", &name, i))
            .stack_size(config.stack_size_bytes)
            .start_handler(move |_idx| {
                let rc = spawned_threads.fetch_add(1, Ordering::Relaxed);
                datapoint_info!("thread-manager-rayon", ("threads-spawned", rc, i64),);
                apply_policy(&core_allocation, policy, priority, &chosen_cores_mask);
            })
            .build()?;
        Ok(Self {
            inner: Arc::new(RayonRuntimeInner { rayon_pool, config }),
        })
    }
}
