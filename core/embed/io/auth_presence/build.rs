use xbuild::{CLibrary, Result, bail_unsupported};

pub fn def_module(lib: &mut CLibrary) -> Result<()> {
    lib.add_include("auth_presence/inc");
    lib.add_define("USE_AUTH_PRESENCE", Some("1"));

    // The same split the vault uses. The header and the define are always added,
    // so the unprivileged application gets the prototype and links the syscall
    // stub for the one call it is allowed to make, while the driver that touches
    // a pin is compiled only where touching a pin is allowed.
    if !cfg!(feature = "secure_mode") && !cfg!(feature = "emulator") {
        return Ok(());
    }

    if cfg!(feature = "emulator") {
        lib.add_source("auth_presence/unix/auth_presence.c");
    } else if cfg!(feature = "mcu_stm32u5") {
        lib.add_source("auth_presence/stm32u5/auth_presence.c");
    } else {
        bail_unsupported!();
    }

    Ok(())
}
