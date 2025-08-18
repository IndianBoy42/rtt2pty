use anyhow::{Context, Result, anyhow, ensure};
use clap::Parser;
use probe_rs::{
    Permissions,
    integration::ProbeLister,
    probe::{DebugProbeSelector, Probe, list::AllProbesLister},
    rtt::{Rtt, ScanRegion, UpChannel},
};
use ptyprocess::PtyProcess;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use std::{
    io::{Read, Write},
    thread,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The chip to connect to.
    #[arg(long)]
    chip: String,

    /// The probe to use, specified as <VID>:<PID>[:<SerialNumber>].
    #[arg(long)]
    probe: Option<String>,

    /// The core to read from
    #[arg(long, default_value_t = 0)]
    core: usize,

    /// The RTT up channel to use for reading from the target.
    #[arg(long, default_value_t = 0)]
    up_channel: usize,

    /// The RTT down channel to use for writing to the target.
    #[arg(long, default_value_t = 0)]
    down_channel: usize,

    /// Use stdio instead of a PTY.
    #[arg(long)]
    stdio: bool,
}

fn rtt_bridge<R: Read, W: Write>(
    core: &mut probe_rs::Core,
    rtt: &mut Rtt,
    up_channel: usize,
    down_channel: usize,
    mut reader: R,
    mut writer: W,
    running: &AtomicBool,
) -> Result<()> {
    let mut rtt_buf = [0u8; 1024];
    let mut host_buf = [0u8; 1024];

    while running.load(Ordering::SeqCst) {
        // RTT -> Host
        match rtt
            .up_channels()
            .get_mut(up_channel)
            .unwrap()
            .read(core, &mut rtt_buf)
        {
            Ok(count) if count > 0 => {
                if writer.write_all(&rtt_buf[..count]).is_err() {
                    eprintln!("Error writing to host. Exiting.");
                    break;
                }
            }
            Ok(_) => {
                // No data.
            }
            Err(e) => {
                eprintln!("Error reading from RTT: {}. Exiting.", e);
                break;
            }
        }

        // Host -> RTT
        match reader.read(&mut host_buf) {
            Ok(count) if count > 0 => {
                if rtt
                    .down_channels()
                    .get_mut(down_channel)
                    .unwrap()
                    .write(core, &host_buf[..count])
                    .is_err()
                {
                    eprintln!("Error writing to RTT. Exiting.");
                    break;
                }
            }
            Ok(_) => {
                // No data.
            }
            Err(e) => {
                // This can happen if the PTY is closed, or if stdin is non-blocking.
                if e.kind() != std::io::ErrorKind::WouldBlock {
                    eprintln!("Error reading from host: {}. Exiting.", e);
                    break;
                }
            }
        }

        // Sleep to avoid busy-looping.
        thread::sleep(Duration::from_millis(10));
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Open the selected probe.
    let selector = if let Some(selector) = &args.probe {
        let selector: DebugProbeSelector = selector
            .as_str()
            .try_into()
            .context("Invalid debug probe selector")?;
        Some(selector)
    } else {
        None
    };
    let probes = AllProbesLister::new().list(selector.as_ref());
    let probe = probes.first().context("Debug probe not found")?.open()?;

    println!("Attaching to the chip...");
    let mut session = probe.attach(&args.chip, Permissions::default())?;

    // Start RTT.
    println!("Starting RTT...");
    let mut rtt = Rtt::attach_region(
        &mut session.core(args.core).context("Core not found")?,
        &ScanRegion::Ram,
    )?;
    ensure!(
        rtt.up_channels().len() > args.up_channel,
        "Up channel {} not found",
        args.up_channel
    );
    ensure!(
        rtt.down_channels().len() > args.down_channel,
        "Down channel {} not found",
        args.down_channel
    );

    // For graceful shutdown.
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .context("Error setting Ctrl-C handler")?;
    let running = &*running;

    let mut core = session.core(args.core).context("Core not found")?;

    if args.stdio {
        // Use stdio
        println!("Using stdio for RTT.");

        #[cfg(unix)]
        {
            use nix::fcntl::{fcntl, FcntlArg, OFlag};
            use std::os::unix::io::AsRawFd;
            // Set stdin to non-blocking.
            let fd = std::io::stdin().as_raw_fd();
            let flags = fcntl(fd, FcntlArg::F_GETFL)?;
            fcntl(
                fd,
                FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
            )?;
            println!("Set stdin to non-blocking.");
        }
        #[cfg(not(unix))]
        {
            println!("Warning: non-blocking stdin is only supported on unix-like systems. Stdin will be blocking, which may not be what you want.");
        }

        println!("Starting RTT <-> stdio bridge. Press Ctrl-C to exit.");
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        rtt_bridge(
            &mut core,
            &mut rtt,
            args.up_channel,
            args.down_channel,
            &stdin,
            &stdout,
            running,
        )?;
    } else {
        // Use PTY
        // Create a new PTY.
        let pty = PtyProcess::spawn(std::process::Command::new("sleep"))?;
        let pty_master = pty.get_raw_handle()?;
        let pty_name = pty.slave_name()?;
        println!(
            "You can now connect to this PTY with a serial terminal, e.g., 'minicom -D {}'",
            pty_name
        );

        println!("Starting RTT <-> PTY bridge. Press Ctrl-C to exit.");

        rtt_bridge(
            &mut core,
            &mut rtt,
            args.up_channel,
            args.down_channel,
            &pty_master,
            &pty_master,
            running,
        )?;
    }

    println!("Exiting.");

    Ok(())
}
