use {
    anyhow::Context,
    aya::{
        include_bytes_aligned,
        maps::{Array, MapData, RingBuf},
        programs::{Xdp, XdpFlags},
        Ebpf,
    },
    aya_log::EbpfLogger,
    log::{error, warn},
    std::{
        net::{IpAddr, Ipv4Addr},
        ops::DerefMut,
    },
    tokio::io::unix::AsyncFd,
    wf_common::{Flags, FILTER_LEN},
};
#[derive(Clone, Copy, Debug, derive_more::Deref, derive_more::DerefMut, derive_more::From)]
pub struct PortPod(Option<u16>);

unsafe impl aya::Pod for PortPod {}
#[derive(Clone, Copy, Debug, derive_more::Deref, derive_more::DerefMut, derive_more::From)]
pub struct IpPod(Option<Ipv4Addr>);

unsafe impl aya::Pod for IpPod {}

pub struct BpfControls {
    _bpf: aya::Ebpf,
    pub rx_ring: AsyncFd<RingBuf<MapData>>,
    src_port: Array<MapData, PortPod>,
    dst_port: Array<MapData, PortPod>,
    src_ip: Array<MapData, IpPod>,
    dst_ip: Array<MapData, IpPod>,
    flags: Array<MapData, Flags>,
}

impl BpfControls {
    pub fn set_flags(&mut self, flags: Flags) -> anyhow::Result<()> {
        self.flags.set(0, flags, 0)?;
        Ok(())
    }

    fn allow<T, V>(map: &mut Array<MapData, T>, new: V) -> anyhow::Result<()>
    where
        T: aya::Pod + DerefMut<Target = Option<V>>,
        T: From<Option<V>>,
        V: Eq + Clone,
    {
        for idx in 0..FILTER_LEN {
            let v = map.get(&idx, 0)?;
            {
                if let Some(v) = v.deref() {
                    // already present
                    if *v == new.clone() {
                        return Ok(());
                    }
                } else {
                    map.set(idx, T::from(Some(new)), 0)?;
                    return Ok(());
                }
            }
        }
        Ok(())
    }
    fn deny_all<T, V>(map: &mut Array<MapData, T>) -> anyhow::Result<()>
    where
        T: aya::Pod,
        T: From<Option<V>>,
    {
        for idx in 0..FILTER_LEN {
            map.set(idx, T::from(None), 0)?;
        }
        Ok(())
    }
    pub fn allow_src_ip(&mut self, new: Ipv4Addr) -> anyhow::Result<()> {
        Self::allow(&mut self.src_ip, new)
    }
    pub fn allow_dst_ip(&mut self, new: Ipv4Addr) -> anyhow::Result<()> {
        Self::allow(&mut self.dst_ip, new)
    }
    pub fn allow_src_port(&mut self, new: u16) -> anyhow::Result<()> {
        Self::allow(&mut self.src_port, new)
    }
    pub fn allow_dst_port(&mut self, new: u16) -> anyhow::Result<()> {
        Self::allow(&mut self.dst_port, new)
    }
    pub fn reset_dst(&mut self) -> anyhow::Result<()> {
        Self::deny_all(&mut self.dst_ip)?;
        Self::deny_all(&mut self.dst_port)
    }
    pub fn new(ifname: &str) -> anyhow::Result<Self> {
        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            error!("remove limit on locked memory failed, ret is: {}", ret);
        }
        // This will include your eBPF object file as raw bytes at compile-time and load it at
        // runtime. This approach is recommended for most real-world use cases. If you would
        // like to specify the eBPF program at runtime rather than at compile-time, you can
        // reach for `Bpf::load_file` instead.
        #[cfg(debug_assertions)]
        let mut bpf = Ebpf::load(include_bytes_aligned!(
            "../wf_ebpf/target/bpfel-unknown-none/debug/wf-ebpf"
        ))?;
        #[cfg(not(debug_assertions))]
        let mut bpf = Ebpf::load(include_bytes_aligned!(
            "../wf_ebpf/target/bpfel-unknown-none/release/wf-ebpf"
        ))?;
        if let Err(e) = EbpfLogger::init(&mut bpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {}", e);
        }
        let program: &mut Xdp = bpf
            .program_mut("wf_ebpf")
            .expect("Program should have entrypoint wf_ebpf")
            .try_into()?;
        program.load()?;
        program
            .attach(ifname, XdpFlags::default())
            .context("failed to attach the XDP program")?;

        let src_ports = Array::try_from(bpf.take_map("ALLOW_SRC_PORTS").unwrap()).unwrap();
        let dst_ports = Array::try_from(bpf.take_map("ALLOW_DST_PORTS").unwrap()).unwrap();
        let dst_ip = Array::try_from(bpf.take_map("ALLOW_DST_IP").unwrap()).unwrap();
        let src_ip = Array::try_from(bpf.take_map("ALLOW_SRC_IP").unwrap()).unwrap();
        let rx_ring = RingBuf::try_from(bpf.take_map("RING_BUF").unwrap()).unwrap();
        let flags = Array::try_from(bpf.take_map("FLAGS").unwrap()).unwrap();
        Ok(BpfControls {
            _bpf: bpf,
            rx_ring: AsyncFd::new(rx_ring)?,
            src_port: src_ports,
            dst_port: dst_ports,
            src_ip,
            flags,
            dst_ip,
        })
    }
}
pub fn v4(a: IpAddr) -> Ipv4Addr {
    match a {
        IpAddr::V4(ipv4_addr) => ipv4_addr,
        IpAddr::V6(_ipv6_addr) => panic!(),
    }
}
