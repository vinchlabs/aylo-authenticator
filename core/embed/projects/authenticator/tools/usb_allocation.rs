use color_eyre::eyre::{Result, bail};

const APPROVED: &str = include_str!("approved_usb_allocations.txt");

fn hex_id(value: &str) -> Result<u16> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| color_eyre::eyre::eyre!("USB ID must use 0x hex notation"))?;
    if digits.len() != 4 {
        bail!("USB ID must contain exactly four hex digits");
    }
    Ok(u16::from_str_radix(digits, 16)?)
}

pub fn approved_identity() -> Result<(u16, u16)> {
    println!("cargo:rerun-if-env-changed=AUTHENTICATOR_USB_VID");
    println!("cargo:rerun-if-env-changed=AUTHENTICATOR_USB_PID");
    let vid = hex_id(&std::env::var("AUTHENTICATOR_USB_VID")?)?;
    let pid = hex_id(&std::env::var("AUTHENTICATOR_USB_PID")?)?;
    if vid == 0 || vid == u16::MAX || pid == 0 || pid == u16::MAX {
        bail!("reserved USB identity is not allowed");
    }
    // Refused for every caller, not only a production one: 1209:53C1 is the
    // fallback a build uses when no identity was supplied, and it belongs to
    // Trezor's pid.codes allocation. Naming it as this project's identity would
    // claim someone else's product id on purpose.
    if (vid, pid) == (0x1209, 0x53c1) {
        bail!("1209:53C1 is the development fallback, not an allocation to supply");
    }
    let mut approved = false;
    let mut seen = std::collections::HashSet::new();
    for line in APPROVED.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() != 2 {
            bail!("malformed approved USB allocation");
        }
        let pair = (hex_id(parts[0])?, hex_id(parts[1])?);
        if pair.0 == 0 || pair.0 == u16::MAX || pair.1 == 0 || pair.1 == u16::MAX
            || pair == (0x1209, 0x53c1)
            || !seen.insert(pair)
        {
            bail!("invalid or duplicate approved USB allocation");
        }
        approved |= pair == (vid, pid);
    }
    if !approved {
        bail!("production USB VID/PID is not in the reviewed allocation list");
    }
    Ok((vid, pid))
}
