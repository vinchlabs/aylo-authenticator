use xbuild::{CLibrary, Result, bail};

pub fn def_module(lib: &mut CLibrary) -> Result<()> {
    if cfg!(feature = "authenticator_test_backend")
        && (!cfg!(feature = "emulator") || cfg!(feature = "production"))
    {
        bail!("authenticator test backend requires a non-production emulator");
    }
    lib.add_include("authenticator/inc");
    lib.add_define("USE_AUTH_VAULT", Some("1"));
    if !cfg!(feature = "secure_mode") && !cfg!(feature = "emulator") {
        return Ok(());
    }
    lib.add_source("authenticator/authenticator.c");
    lib.add_source("authenticator/authenticator_call.c");
    // Pure codec, no OPTIGA/storage dependency; backend-agnostic.
    lib.add_source("authenticator/replica_format.c");
    // Replica selection/transaction manager. Reaches flash only through the
    // caller-supplied auth_replica_io callbacks, so it links without any
    // platform flash dependency of its own.
    lib.add_source("authenticator/replica_store.c");
    // Translates the manager's snapshot model into the vault's record/result
    // vocabulary. Platform independent for the same reason.
    lib.add_source("authenticator/replica_records.c");
    if cfg!(feature = "authenticator_test_backend") {
        lib.add_define("AUTH_TEST_BACKEND", Some("1"));
    }
    if cfg!(feature = "emulator") {
        lib.add_source("authenticator/unix/authenticator_backend.c");
    } else {
        if !cfg!(feature = "optiga") {
            bail!("authenticator hardware vault requires OPTIGA");
        }
        // Ordinary storage is the opposite of a requirement here. The vault owns
        // the raw bytes of STORAGE_AREAS[0] and STORAGE_AREAS[1] as replicas 0
        // and 1, so a linked NORCOW writes into vault territory instead of
        // sharing a keyspace with it, as it did before the replica swap.
        if cfg!(feature = "storage") {
            bail!(
                "authenticator vault owns the storage areas; ordinary storage must not be linked"
            );
        }
        lib.add_source("authenticator/stm32u5/authenticator_backend.c");
        lib.add_source("authenticator/stm32u5/authenticator_storage.c");
        // The only translation unit that maps a replica index onto a physical
        // flash area. Reaches flash through the checked reader, never through a
        // mapped pointer.
        lib.add_source("authenticator/stm32u5/authenticator_replica_io.c");
    }
    Ok(())
}
