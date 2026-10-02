use std::io::IsTerminal;
use std::{env, io, process};

use anyhow::{Result, bail};

use crate::args::{Model, Project};
use crate::options::ResolvedBuildArgs;
use crate::{config, helpers};

#[derive(Debug)]
pub struct ResolvedBuildFeatures {
    pub features: Vec<String>,
    pub target_triple: Option<&'static str>,
    pub board_header: String,
}

/// Resolves cargo features and target triple from the provided build
/// arguments.
///
/// Option-dependent features come from the `[build-options]` table of the
/// project's project.toml; board- and model-intrinsic features come from the
/// model/board TOML configs filtered by the project's `uses` list. Only
/// features tied to build mechanics (model selection, emulator, asan) are
/// added directly here.
pub fn resolve_features(args: &ResolvedBuildArgs) -> Result<ResolvedBuildFeatures> {
    if args.production {
        if args.storage_insecure_testing_mode {
            bail!("storage_insecure_testing_mode cannot be used in production builds");
        }
        if args.disable_optiga {
            bail!("disable_optiga cannot be used in production builds");
        }
        if args.disable_tropic {
            bail!("disable_tropic cannot be used in production builds");
        }
    }

    if args.headless_dev {
        if args.project != Project::Bootloader {
            bail!("headless_dev is supported only for the bootloader project");
        }
        if args.model != Model::T3T1 || args.emulator {
            bail!("headless_dev is supported only for T3T1 hardware builds");
        }
        // --bootloader-devel is no longer required, and requiring it was a mistake:
        // that flag substitutes the published development keys for the model's
        // MODEL_BOOTLOADER_KEYS and MODEL_BOARDLOADER_KEYS, so insisting on it meant a
        // headless build could only ever be signed by keys whose private halves are
        // public. Activation step 2 needs the opposite -- headless, carrying this
        // project's own keys -- so only the production clause remains, because there is
        // no display on this board to show anything a production build would confirm.
        if args.production {
            bail!("headless_dev forbids --production: the UI workflows are compiled out");
        }
    }

    let mut features: Vec<String> = vec![args.model.feature_name()];

    if args.authenticator_kernel {
        if args.project != Project::Kernel || args.model != Model::T3T1 || args.emulator {
            bail!("authenticator kernel is only supported for T3T1 hardware");
        }
    }

    if args.emulator {
        features.push("emulator".into());
    }

    let project_config = config::ProjectConfig::load(args.project)?;

    for activated in project_config.options.resolve(args) {
        features.push(activated.feature);
    }

    let model_config = args.model.config()?;

    let board_id = args
        .board
        .clone()
        .unwrap_or_else(|| model_config.default_board.clone());

    let board_def = config::resolve_board_definition(
        &model_config,
        &board_id,
        &project_config,
        args.project,
        args.emulator,
    )?;

    // Remove features that are disabled by command-line flags.
    let mut board_features = board_def.features;
    if args.disable_optiga {
        board_features.retain(|f| f != "optiga");
    }
    if args.disable_tropic {
        board_features.retain(|f| f != "tropic");
    }
    features.extend(board_features);

    if args.authenticator_kernel {
        features = vec![
            args.model.feature_name(),
            "mcu_stm32u58".into(),
            "authenticator".into(),
        ];
        if args.bootloader_devel {
            features.push("bootloader_devel".into());
        }
        if args.production {
            features.push("production".into());
        }
    }

    let target_triple = if args.emulator {
        None
    } else {
        Some(model_config.target_triple()?)
    };

    Ok(ResolvedBuildFeatures {
        features,
        target_triple,
        board_header: board_def.board_header,
    })
}

/// Resolves `CARGO_TERM_COLOR` to `always`/`never` for the spawned Cargo.
///
/// Build scripts see only pipes (Cargo captures their output), so `xtask` -
/// the last process attached to the real terminal - decides for them; `xbuild`
/// reads the result to color C compiler diagnostics. An explicit
/// `always`/`never` in the environment is left alone (the child inherits it).
fn forward_color_choice(cmd: &mut process::Command) {
    let explicit = env::var("CARGO_TERM_COLOR").is_ok_and(|v| v == "always" || v == "never");
    if explicit {
        return;
    }

    // https://no-color.org
    let color = if env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        "never"
    // https://bixense.com/clicolors
    } else if io::stderr().is_terminal()
        || env::var_os("CLICOLOR_FORCE").is_some_and(|v| !v.is_empty() && v != "0")
    {
        "always"
    } else {
        "never"
    };

    cmd.env("CARGO_TERM_COLOR", color);
}

/// Configures a cargo command with the appropriate arguments and features.
pub fn configure_cargo(args: &ResolvedBuildArgs, cmd: &mut process::Command) -> Result<()> {
    let resolved = resolve_features(args)?;
    let mut rebuild_std = false;

    cmd.args(["--package", args.project.package_name()]);
    if args.authenticator_kernel {
        cmd.arg("--no-default-features");
    }
    cmd.args(["--features", &resolved.features.join(",")]);
    cmd.args(["--profile", args.cargo_profile_name()]);
    cmd.env("TREZOR_BOARD_HEADER", &resolved.board_header);
    cmd.env("SCM_REVISION", helpers::git_revision()?);

    if args.cargo_profile_name() == "release" {
        // Required by panic-immediate-abort in the release profile
        rebuild_std = true;
    }

    if let Some(triple) = resolved.target_triple {
        cmd.args(["--target", triple]);
    }

    if args.emit_memory_analysis {
        // See https://nnethercote.github.io/perf-book/type-sizes.html#measuring-type-sizes for more details
        // Also adds an ELF section with Rust functions' stack sizes. See:
        // - https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/emit-stack-sizes.html
        // - https://blog.japaric.io/stack-analysis/
        // - https://github.com/japaric/stack-sizes/
        //
        // Use --config instead of RUSTFLAGS env so that rustflags in .cargo/config.toml
        // are not overridden (RUSTFLAGS env has higher precedence and replaces
        // them entirely).
        cmd.args([
            "--config",
            "build.rustflags=[\"-Zprint-type-sizes\", \"-Zemit-stack-sizes\"]",
        ]);
    }

    if args.emulator && args.asan {
        // -Zsanitizer=address is a rustc flag passed via RUSTFLAGS.
        //
        // Without an explicit --target, cargo compiles proc-macros and the firmware in
        // the same pass and RUSTFLAGS leaks into proc-macro crates, causing
        // "can't find crate" errors. Passing --target explicitly (even the same
        // triple as the host) makes cargo separate the host (proc-macros /
        // build scripts) and target (firmware) compilation units, so RUSTFLAGS
        // only reaches the firmware crates.
        cmd.args(["--target", &helpers::host_triple()?]);
        cmd.args([
            "--config",
            "build.rustflags=[\"-Zsanitizer=address\", \"-Clink-arg=-lgcc_s\"]",
        ]);

        // Rebuild standard library to be compiled with sanitizer instrumentation
        rebuild_std = true;
    }

    if args.timings {
        cmd.arg("--timings");
    }

    if args.xbuild_trace {
        // Cargo does not pass its own verbosity on to build scripts, so
        // `xbuild` reads the request from the environment instead.
        cmd.env("XBUILD_TRACE", "1");
        // `-vv`, not `-v`: Cargo relays build script output only at the second
        // verbosity level, and would otherwise discard what `xbuild` logs.
        cmd.arg("-vv");
    } else if args.verbose {
        cmd.arg("--verbose");
    }

    if rebuild_std {
        cmd.arg("-Zbuild-std=core");
    }

    forward_color_choice(cmd);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::Project;

    #[test]
    fn authenticator_kernel_excludes_display_and_wire() {
        let args = ResolvedBuildArgs {
            project: Project::Kernel,
            model: Model::T3T1,
            authenticator_kernel: true,
            ..ResolvedBuildArgs::default()
        };
        let resolved = resolve_features(&args).unwrap();
        assert!(resolved.features.contains(&"authenticator".to_string()));
        assert!(!resolved.features.iter().any(|feature| matches!(
            feature.as_str(),
            "display" | "touch" | "dma2d" | "framebuffer" | "universal_fw"
        )));
        let mut command = process::Command::new("cargo");
        configure_cargo(&args, &mut command).unwrap();
        assert!(command.get_args().any(|arg| arg == "--no-default-features"));
    }

    #[test]
    fn authenticator_kernel_closes_the_applet_window_onto_the_vault_areas() {
        // The assets area is replica 2 on this project, and the MPU's application
        // mode maps it read-only-unprivileged on every other model so that a UI
        // applet can dereference the pointer translations_read() returns. mpu.c is
        // compiled into the `sys` library, which never sees the AUTHENTICATOR
        // define the kernel adds to its own sources, so the exclusion has to
        // travel as a cargo feature or it silently does nothing at all.
        let args = ResolvedBuildArgs {
            project: Project::Kernel,
            model: Model::T3T1,
            authenticator_kernel: true,
            ..ResolvedBuildArgs::default()
        };
        let resolved = resolve_features(&args).unwrap();
        assert!(resolved.features.contains(&"authenticator".to_string()));
    }

    #[test]
    fn rejects_insecure_storage_in_production_builds() {
        let args = ResolvedBuildArgs {
            production: true,
            storage_insecure_testing_mode: true,
            ..ResolvedBuildArgs::default()
        };

        let error = resolve_features(&args).unwrap_err();
        assert!(error.to_string().contains("production"));
    }

    #[test]
    fn rejects_disable_optiga_in_production_builds() {
        let args = ResolvedBuildArgs {
            production: true,
            disable_optiga: true,
            ..ResolvedBuildArgs::default()
        };

        let error = resolve_features(&args).unwrap_err();
        assert!(error.to_string().contains("production"));
    }

    #[test]
    fn rejects_disable_tropic_in_production_builds() {
        let args = ResolvedBuildArgs {
            production: true,
            disable_tropic: true,
            ..ResolvedBuildArgs::default()
        };

        let error = resolve_features(&args).unwrap_err();
        assert!(error.to_string().contains("production"));
    }

    #[test]
    fn accepts_explicit_t3t1_headless_development_bootloader() {
        let args = ResolvedBuildArgs {
            project: Project::Bootloader,
            model: Model::T3T1,
            bootloader_devel: true,
            headless_dev: true,
            ..ResolvedBuildArgs::default()
        };

        let features = resolve_features(&args).unwrap().features;
        assert!(features.contains(&"headless_dev".to_string()));
    }

    #[test]
    fn rejects_headless_dev_without_development_bootloader() {
        let args = ResolvedBuildArgs {
            project: Project::Bootloader,
            model: Model::T3T1,
            headless_dev: true,
            ..ResolvedBuildArgs::default()
        };

        assert!(resolve_features(&args).is_err());
    }

    #[test]
    fn rejects_headless_dev_for_production_or_other_targets() {
        for args in [
            ResolvedBuildArgs {
                project: Project::Bootloader,
                model: Model::T3T1,
                bootloader_devel: true,
                headless_dev: true,
                production: true,
                ..ResolvedBuildArgs::default()
            },
            ResolvedBuildArgs {
                project: Project::Bootloader,
                model: Model::T3W1,
                bootloader_devel: true,
                headless_dev: true,
                ..ResolvedBuildArgs::default()
            },
            ResolvedBuildArgs {
                project: Project::Firmware,
                model: Model::T3T1,
                bootloader_devel: true,
                headless_dev: true,
                ..ResolvedBuildArgs::default()
            },
        ] {
            assert!(resolve_features(&args).is_err());
        }
    }

    #[test]
    fn ignores_options_the_project_does_not_map() {
        // prodtest doesn't map `disable-animation` (the package has no such
        // feature), so the option is ignored like any other unmapped option.
        let args = ResolvedBuildArgs {
            project: Project::Prodtest,
            frozen: true,
            pyopt: true,
            disable_animation: true,
            ..ResolvedBuildArgs::default()
        };

        let features = resolve_features(&args).unwrap().features;
        assert!(!features.contains(&"disable_animation".to_string()));
    }
}
