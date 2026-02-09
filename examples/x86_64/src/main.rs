#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

#[macro_use]
extern crate log;
extern crate alloc;

mod boot;
mod hal;
mod heap;
mod logger;
mod trap;

#[cfg(feature = "tcp")]
mod tcp;

use self::hal::HalImpl;
use virtio_drivers::{
    device::{blk::VirtIOBlk, gpu::VirtIOGpu, rng::VirtIORng, virtio_9p::VirtIO9p},
    transport::{
        pci::{
            bus::{BarInfo, Cam, Command, ConfigurationAccess, DeviceFunction, MmioCam, PciRoot},
            virtio_device_type, PciTransport,
        },
        DeviceType, Transport,
    },
};

/// Memory mapped address space to access PCI configuration.
///
/// Currently it is hardcoded (from qemu/roms/seabios/src/hw/dev-q35.h)
///
/// TODO: get it from ACPI MCFG table.
const MMCONFIG_BASE: usize = 0xB000_0000;

const NET_QUEUE_SIZE: usize = 16;

fn system_off() -> ! {
    use x86_64::instructions::{hlt, port::PortWriteOnly};
    unsafe {
        PortWriteOnly::new(0x604).write(0x2000u16);
        loop {
            hlt();
        }
    }
}

#[no_mangle]
extern "C" fn main(_mbi: *const u8) -> ! {
    logger::init(log::LevelFilter::Info).unwrap();
    info!("virtio-drivers example started.");

    trap::init();
    heap::init_heap();

    enumerate_pci(MMCONFIG_BASE as _);

    info!("test end");
    system_off();
}

fn virtio_device(transport: impl Transport) {
    match transport.device_type() {
        DeviceType::Block => virtio_blk(transport),
        DeviceType::GPU => virtio_gpu(transport),
        DeviceType::Network => virtio_net(transport),
        DeviceType::_9P => virtio_9p(transport),
        DeviceType::EntropySource => virtio_rng(transport),
        t => warn!("Unrecognized virtio device: {:?}", t),
    }
}

fn virtio_rng<T: Transport>(transport: T) {
    let mut bytes = [0u8; 8];
    let mut rng = VirtIORng::<HalImpl, T>::new(transport).expect("failed to create rng driver");
    let len = rng
        .request_entropy(&mut bytes)
        .expect("failed to receive entropy");
    info!("received {len} random bytes: {:?}", &bytes[..len]);
    info!("virtio-rng test finished");
}

fn virtio_blk<T: Transport>(transport: T) {
    let mut blk = VirtIOBlk::<HalImpl, T>::new(transport).expect("failed to create blk driver");
    assert!(!blk.readonly());
    let mut input = [0xffu8; 512];
    let mut output = [0; 512];
    for i in 0..32 {
        for x in input.iter_mut() {
            *x = i as u8;
        }
        blk.write_blocks(i, &input).expect("failed to write");
        blk.read_blocks(i, &mut output).expect("failed to read");
        assert_eq!(input, output);
    }
    info!("virtio-blk test finished");
}

fn virtio_9p<T: Transport>(transport: T) {
    let mut p9 = VirtIO9p::<HalImpl, T>::new(transport).expect("failed to create 9p driver");
    info!("virtio-9p mount tag: {}", p9.mount_tag());

    let mut req = [0u8; 128];
    let mut resp = [0u8; 256];
    let req_len = build_tversion_request(&mut req, 16384, "9P2000.L")
        .expect("failed to build 9p Tversion request");
    let resp_len = p9
        .request(&req[..req_len], &mut resp)
        .expect("failed to send 9p request");
    parse_rversion_response(&resp[..resp_len]).expect("invalid 9p Rversion response");
    info!("virtio-9p test finished");
}

fn build_tversion_request(buf: &mut [u8], msize: u32, version: &str) -> Option<usize> {
    const TVERSION: u8 = 100;
    const NOTAG: u16 = 0xffff;

    let vbytes = version.as_bytes();
    let size = 4 + 1 + 2 + 4 + 2 + vbytes.len();
    if buf.len() < size || vbytes.len() > u16::MAX as usize {
        return None;
    }

    buf[0..4].copy_from_slice(&(size as u32).to_le_bytes());
    buf[4] = TVERSION;
    buf[5..7].copy_from_slice(&NOTAG.to_le_bytes());
    buf[7..11].copy_from_slice(&msize.to_le_bytes());
    buf[11..13].copy_from_slice(&(vbytes.len() as u16).to_le_bytes());
    buf[13..13 + vbytes.len()].copy_from_slice(vbytes);
    Some(size)
}

fn parse_rversion_response(resp: &[u8]) -> Option<()> {
    const RVERSION: u8 = 101;
    const NOTAG: u16 = 0xffff;

    if resp.len() < 13 {
        return None;
    }

    let size = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]) as usize;
    if size > resp.len() {
        return None;
    }
    if resp[4] != RVERSION {
        return None;
    }
    if u16::from_le_bytes([resp[5], resp[6]]) != NOTAG {
        return None;
    }

    let msize = u32::from_le_bytes([resp[7], resp[8], resp[9], resp[10]]);
    let name_len = u16::from_le_bytes([resp[11], resp[12]]) as usize;
    let name_end = 13 + name_len;
    if name_end > size {
        return None;
    }
    let version = core::str::from_utf8(&resp[13..name_end]).ok()?;
    info!("virtio-9p rversion: msize={}, version={}", msize, version);
    Some(())
}

fn virtio_gpu<T: Transport>(transport: T) {
    let mut gpu = VirtIOGpu::<HalImpl, T>::new(transport).expect("failed to create gpu driver");
    let (width, height) = gpu.resolution().expect("failed to get resolution");
    let width = width as usize;
    let height = height as usize;
    info!("GPU resolution is {}x{}", width, height);
    let fb = gpu.setup_framebuffer().expect("failed to get fb");
    for y in 0..height {
        for x in 0..width {
            let idx = (y * width + x) * 4;
            fb[idx] = x as u8;
            fb[idx + 1] = y as u8;
            fb[idx + 2] = (x + y) as u8;
        }
    }
    gpu.flush().expect("failed to flush");
    //delay some time
    info!("virtio-gpu show graphics....");
    for _ in 0..10000 {
        for _ in 0..100000 {
            unsafe {
                core::arch::asm!("nop");
            }
        }
    }

    info!("virtio-gpu test finished");
}

fn virtio_net<T: Transport>(transport: T) {
    #[cfg(not(feature = "tcp"))]
    {
        let mut net =
            virtio_drivers::device::net::VirtIONetRaw::<HalImpl, T, NET_QUEUE_SIZE>::new(transport)
                .expect("failed to create net driver");
        info!("MAC address: {:02x?}", net.mac_address());

        let mut buf = [0u8; 2048];
        let (hdr_len, pkt_len) = net.receive_wait(&mut buf).expect("failed to recv");
        info!(
            "recv {} bytes: {:02x?}",
            pkt_len,
            &buf[hdr_len..hdr_len + pkt_len]
        );
        net.send(&buf[..hdr_len + pkt_len]).expect("failed to send");
        info!("virtio-net test finished");
    }

    #[cfg(feature = "tcp")]
    {
        const NET_BUFFER_LEN: usize = 2048;
        let net = virtio_drivers::device::net::VirtIONet::<HalImpl, T, NET_QUEUE_SIZE>::new(
            transport,
            NET_BUFFER_LEN,
        )
        .expect("failed to create net driver");
        info!("MAC address: {:02x?}", net.mac_address());
        tcp::test_echo_server(net);
    }
}

fn enumerate_pci(mmconfig_base: *mut u8) {
    info!("mmconfig_base = {:#x}", mmconfig_base as usize);

    let mut pci_root = PciRoot::new(unsafe { MmioCam::new(mmconfig_base, Cam::Ecam) });
    for (device_function, info) in pci_root.enumerate_bus(0) {
        let (status, command) = pci_root.get_status_command(device_function);
        info!(
            "Found {} at {}, status {:?} command {:?}",
            info, device_function, status, command
        );
        if let Some(virtio_type) = virtio_device_type(&info) {
            info!("  VirtIO {:?}", virtio_type);

            // Enable the device to use its BARs.
            pci_root.set_command(
                device_function,
                Command::IO_SPACE | Command::MEMORY_SPACE | Command::BUS_MASTER,
            );
            dump_bar_contents(&mut pci_root, device_function, 4);

            let mut transport =
                PciTransport::new::<HalImpl, _>(&mut pci_root, device_function).unwrap();
            info!(
                "Detected virtio PCI device with device type {:?}, features {:#018x}",
                transport.device_type(),
                transport.read_device_features(),
            );
            virtio_device(transport);
        }
    }
}

fn dump_bar_contents(
    root: &mut PciRoot<impl ConfigurationAccess>,
    device_function: DeviceFunction,
    bar_index: u8,
) {
    let bar_info = root.bar_info(device_function, bar_index).unwrap();
    trace!("Dumping bar {}: {:#x?}", bar_index, bar_info);
    if let Some(BarInfo::Memory { address, size, .. }) = bar_info {
        let start = address as *const u8;
        unsafe {
            let mut buf = [0u8; 32];
            for i in 0..size / 32 {
                let ptr = start.add(i as usize * 32);
                core::ptr::copy(ptr, buf.as_mut_ptr(), 32);
                if buf.iter().any(|b| *b != 0xff) {
                    trace!("  {:?}: {:x?}", ptr, buf);
                }
            }
        }
    }
    trace!("End of dump");
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    error!("{}", info);
    system_off()
}
