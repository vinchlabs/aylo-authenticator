use xbuild::{CLibrary, Result, bail_unsupported};

pub fn def_module(lib: &mut CLibrary) -> Result<()> {
    lib.add_include("mpu/inc");

    // The define has to be added here rather than relied upon from the project.
    // mpu.c is compiled into the `sys` library, which does not see the
    // AUTHENTICATOR define that projects/kernel/build.rs adds to its own
    // sources; an #ifdef on that name would silently never fire.
    if cfg!(feature = "authenticator_vault_areas") {
        lib.add_define("AUTHENTICATOR_VAULT_AREAS", Some("1"));
    }

    if cfg!(feature = "emulator") {
        lib.add_source("mpu/unix/mpu.c");
    } else if cfg!(feature = "mcu_stm32f4") {
        lib.add_source("mpu/stm32f4/mpu.c");
    } else if cfg!(feature = "mcu_stm32u5") {
        lib.add_source("mpu/stm32u5/mpu.c");
    } else {
        bail_unsupported!();
    }

    Ok(())
}
