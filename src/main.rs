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

    // Create a new PTY.
    let pty = PtyProcess::spawn(std::process::Command::new("sleep"))?;
    let mut pty_master = pty.get_raw_handle()?;
    let pty_name = pty.slave_name()?;
    println!(
        "You can now connect to this PTY with a serial terminal, e.g., 'minicom -D {}'",
        pty_name
    );

    // For graceful shutdown.
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .context("Error setting Ctrl-C handler")?;
    let running = &*running;

    println!("Starting RTT <-> PTY bridge. Press Ctrl-C to exit.");

    let mut core = session.core(args.core).context("Core not found")?;

    let mut rtt_buf = [0u8; 1024];
    let mut pty_buf = [0u8; 1024];

    while running.load(Ordering::SeqCst) {
        // RTT -> PTY
        match rtt
            .up_channels()
            .get_mut(args.up_channel)
            .unwrap()
            .read(&mut core, &mut rtt_buf)
        {
            Ok(count) if count > 0 => {
                if pty_master.write_all(&rtt_buf[..count]).is_err() {
                    eprintln!("Error writing to PTY. Exiting.");
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

        // PTY -> RTT
        match pty_master.read(&mut pty_buf) {
            Ok(count) if count > 0 => {
                if rtt
                    .down_channels()
                    .get_mut(args.down_channel)
                    .unwrap()
                    .write(&mut core, &pty_buf[..count])
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
                // This can happen if the PTY is closed.
                if e.kind() != std::io::ErrorKind::WouldBlock {
                    eprintln!("Error reading from PTY: {}. Exiting.", e);
                    break;
                }
            }
        }

        // Sleep to avoid busy-looping.
        thread::sleep(Duration::from_millis(10));
    }

    println!("Exiting.");

    Ok(())
}
