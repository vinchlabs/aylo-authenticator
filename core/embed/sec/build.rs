use xbuild::{Result, build_mods};

#[path = "authenticator/build.rs"]
mod authenticator;

#[path = "backup_ram/build.rs"]
mod backup_ram;
#[path = "board_capabilities/build.rs"]
mod board_capabilities;
#[path = "consumption_mask/build.rs"]
mod consumption_mask;
#[path = "fwutils/build.rs"]
mod fwutils;
#[path = "hash_processor/build.rs"]
mod hash_processor;
#[path = "hw_revision/build.rs"]
mod hw_revision;
#[path = "image/build.rs"]
mod image;
#[path = "iwdg/build.rs"]
mod iwdg;
#[path = "mcu_attestation/build.rs"]
mod mcu_attestation;
#[path = "mldsa44/build.rs"]
mod mldsa44;
#[path = "monoctr/build.rs"]
mod monoctr;
#[path = "optiga/build.rs"]
mod optiga;
#[path = "option_bytes/build.rs"]
mod option_bytes;
#[path = "random_delays/build.rs"]
mod random_delays;
#[path = "rng/build.rs"]
mod rng;
#[path = "rsod/build.rs"]
mod rsod;
#[path = "secret/build.rs"]
mod secret;
#[path = "secret_keys/build.rs"]
mod secret_keys;
#[path = "secure_aes/build.rs"]
mod secure_aes;
#[path = "storage/build.rs"]
mod storage;
#[path = "suspend/build.rs"]
mod suspend;
#[path = "tamper/build.rs"]
mod tamper;
#[path = "telemetry/build.rs"]
mod telemetry;
#[path = "time_estimate/build.rs"]
mod time_estimate;
#[path = "tropic/build.rs"]
mod tropic;
#[path = "trustzone/build.rs"]
mod trustzone;
#[path = "unit_properties/build.rs"]
mod unit_properties;

fn main() -> Result<()> {
    xbuild::build(|lib| {
        lib.import_lib("sys")?;

        build_mods!(
            lib,
            [
                authenticator if cfg!(feature = "authenticator"),
                backup_ram if cfg!(feature = "backup_ram"),
                board_capabilities,
                consumption_mask if cfg!(feature = "consumption_mask"),
                fwutils,
                hash_processor if cfg!(feature = "hash_processor"),
                hw_revision if cfg!(feature = "hw_revision"),
                mcu_attestation if cfg!(feature = "mcu_attestation"),
                mldsa44 if cfg!(feature = "mldsa44"),
                monoctr,
                option_bytes,
                image,
                iwdg if cfg!(feature = "iwdg"),
                optiga if cfg!(feature = "optiga"),
                random_delays,
                rng,
                rsod,
                secret if cfg!(feature = "secret"),
                secret_keys,
                secure_aes if cfg!(feature = "secure_aes"),
                storage if cfg!(feature = "storage"),
                suspend if cfg!(feature = "suspend"),
                tamper if cfg!(feature = "tamper"),
                telemetry if cfg!(feature = "telemetry"),
                time_estimate if cfg!(feature = "time_estimate"),
                tropic if cfg!(feature = "tropic"),
                trustzone if cfg!(feature = "trustzone"),
                unit_properties,
            ]
        );

        // The authenticator links no ordinary storage: the vault owns the raw
        // bytes of STORAGE_AREAS[0] and STORAGE_AREAS[1] as replicas 0 and 1, so
        // NORCOW there would write into vault territory. It still needs the
        // header, because optiga.h includes <sec/storage.h> for PIN_MAX_TRIES and
        // STRETCHED_PIN_COUNT -- secure-element retry constants that happen to
        // live in the storage header rather than anything NORCOW does. So the
        // include path is added on its own: no sources, and deliberately no
        // USE_STORAGE, which would tell the rest of the tree a storage engine is
        // present.
        if cfg!(feature = "authenticator") && cfg!(not(feature = "storage")) {
            lib.add_include("storage/inc");
        }
        if cfg!(feature = "bootloader_devel") {
            lib.add_define("BOOTLOADER_DEVEL", Some("1"));
        }

        if cfg!(not(feature = "emulator")) && cfg!(not(feature = "secure_mode")) {
            // Linking sec layer in non-secure mode
            lib.add_source("../sys/smcall/stm32/smcall_stubs.c");
        }

        if cfg!(feature = "test") {
            lib.add_source("src/test_setup.c");
            lib.add_include("authenticator/inc");
            lib.add_source("authenticator/tests/test_authenticator.c");
            lib.add_source("authenticator/tests/test_authenticator_crypto.c");
            lib.add_source("authenticator/tests/test_authenticator_call.c");
            lib.add_include("optiga/inc");
            lib.add_include("storage/inc");
            lib.add_source("authenticator/tests/test_optiga_backend.c");
        }

        Ok(())
    })
}
