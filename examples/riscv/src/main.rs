#![no_std]
#![no_main]
#![deny(warnings)]

#[macro_use]
extern crate log;

extern crate alloc;
extern crate opensbi_rt;

use alloc::vec;
use core::ptr::NonNull;
use flat_device_tree::{node::FdtNode, standard_nodes::Compatible, Fdt};
use log::LevelFilter;
use virtio_drivers::{
    device::{
        blk::VirtIOBlk,
        gpu::VirtIOGpu,
        input::VirtIOInput,
        rng::VirtIORng,
        sound::{PcmFormat, PcmRate, VirtIOSound},
        virtio_9p::VirtIO9p,
    },
    transport::{
        mmio::{MmioTransport, VirtIOHeader},
        DeviceType, Transport,
    },
};
use virtio_impl::HalImpl;

mod virtio_impl;

#[cfg(feature = "tcp")]
mod tcp;

const NET_QUEUE_SIZE: usize = 16;

#[no_mangle]
extern "C" fn main(_hartid: usize, device_tree_paddr: usize) {
    log::set_max_level(LevelFilter::Info);
    init_dt(device_tree_paddr);
    info!("test end");
}

fn init_dt(dtb: usize) {
    info!("device tree @ {:#x}", dtb);
    // Safe because the pointer is a valid pointer to unaliased memory.
    let fdt = unsafe { Fdt::from_ptr(dtb as *const u8).unwrap() };
    walk_dt(fdt);
}

fn walk_dt(fdt: Fdt) {
    for node in fdt.all_nodes() {
        if let Some(compatible) = node.compatible() {
            if compatible.all().any(|s| s == "virtio,mmio") {
                virtio_probe(node);
            }
        }
    }
}

fn virtio_probe(node: FdtNode) {
    if let Some(reg) = node.reg().next() {
        let paddr = reg.starting_address as usize;
        let size = reg.size.unwrap();
        let vaddr = paddr;
        info!("walk dt addr={:#x}, size={:#x}", paddr, size);
        info!(
            "Device tree node {}: {:?}",
            node.name,
            node.compatible().map(Compatible::first),
        );
        let header = NonNull::new(vaddr as *mut VirtIOHeader).unwrap();
        match unsafe { MmioTransport::new(header, size) } {
            Err(e) => warn!("Error creating VirtIO MMIO transport: {}", e),
            Ok(transport) => {
                info!(
                    "Detected virtio MMIO device with vendor id {:#X}, device type {:?}, version {:?}",
                    transport.vendor_id(),
                    transport.device_type(),
                    transport.version(),
                );
                virtio_device(transport);
            }
        }
    }
}

fn virtio_device(transport: impl Transport) {
    match transport.device_type() {
        DeviceType::Block => virtio_blk(transport),
        DeviceType::GPU => virtio_gpu(transport),
        DeviceType::Input => virtio_input(transport),
        DeviceType::Network => virtio_net(transport),
        DeviceType::Sound => virtio_sound(transport),
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
    let mut input = vec![0xffu8; 512];
    let mut output = vec![0; 512];
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

fn virtio_input<T: Transport>(transport: T) {
    //let mut event_buf = [0u64; 32];
    let mut _input =
        VirtIOInput::<HalImpl, T>::new(transport).expect("failed to create input driver");
    // loop {
    //     input.ack_interrupt().expect("failed to ack");
    //     info!("mouse: {:?}", input.mouse_xy());
    // }
    // TODO: handle external interrupt
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

fn virtio_sound<T: Transport>(transport: T) {
    let mut sound =
        VirtIOSound::<HalImpl, T>::new(transport).expect("failed to create sound driver");
    let output_streams = sound.output_streams().unwrap();
    if !output_streams.is_empty() {
        let output_stream_id = *output_streams.first().unwrap();
        let rates = sound.rates_supported(output_stream_id).unwrap();
        let formats = sound.formats_supported(output_stream_id).unwrap();
        let channel_range = sound.channel_range_supported(output_stream_id).unwrap();
        let features = sound.features_supported(output_stream_id).unwrap();

        let rate = if rates.contains(PcmRate::Rate44100.into()) {
            PcmRate::Rate44100
        } else {
            PcmRate::Rate32000
        };
        let format = if formats.contains(PcmFormat::U8.into()) {
            PcmFormat::U8
        } else {
            PcmFormat::U32
        };
        let channel = if channel_range.contains(&2) {
            2
        } else {
            *channel_range.start()
        };
        sound
            .pcm_set_params(
                output_stream_id,
                4410 * 2,
                4410,
                features,
                channel,
                format,
                rate,
            )
            .expect("pcm_set_params error");
        sound
            .pcm_prepare(output_stream_id)
            .expect("pcm_prepare error");
        sound.pcm_start(output_stream_id).expect("pcm_start error");
        let music = include_bytes!("../music_44100Hz_u8_stereo.raw");
        info!("[sound device] music len is {} bytes.", music.len());
        // xfer buffer
        sound
            .pcm_xfer(output_stream_id, &music[..])
            .expect("pcm_xfer error");
        sound.pcm_stop(output_stream_id).expect("pcm_stop error");
        sound
            .pcm_release(output_stream_id)
            .expect("pcm_release error");
        match sound.latest_notification() {
            Ok(notification) => info!("{:?}", notification),
            Err(e) => warn!("{}", e),
        }
    }
}
