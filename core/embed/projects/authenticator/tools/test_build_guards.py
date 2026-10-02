"""Compile and execute the actual pre-link guards with independent feature flags."""
import pathlib
import re
import subprocess
import tempfile
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "build.rs"


class BuildGuardTests(unittest.TestCase):
    def test_release_and_hardware_reject_each_test_feature_independently(self):
        source = SOURCE.read_text()
        start = source.index("fn main() -> Result<()> {") + len("fn main() -> Result<()> {")
        end = source.index('xbuild::build_and_link("authenticator"', start)
        guards = source[start:end]
        program = """
type Result<T> = std::result::Result<T, String>;
macro_rules! bail { ($message:expr) => { return Err($message.into()) }; }
mod usb_allocation {
    pub fn approved_identity() -> Result<(), String> {
        Err("production identity must not be consulted before test rejection".into())
    }
}
fn guard() -> Result<()> {
""" + guards + """
    Ok(())
}
fn main() {
    match guard() {
        Ok(()) => println!("PASS"),
        Err(error) => { println!("{}", error); std::process::exit(2); }
    }
}
"""
        cases = (
            ((), "PASS"),
            (("authenticator_test_presence",), "authenticator test presence is emulator-only"),
            (("authenticator_test_backend",), "authenticator test backend is emulator-only"),
            (("emulator", "production", "authenticator_test_presence"),
             "authenticator test features are forbidden in production"),
            (("emulator", "production", "authenticator_test_backend"),
             "authenticator test features are forbidden in production"),
            (("emulator", "authenticator_test_presence"), "PASS"),
            (("emulator", "authenticator_test_backend"), "PASS"),
            # Assumed presence is the one mode meant for hardware, because the
            # gesture this board has is not wired up yet. So it passes where the
            # emulator-only features are refused, and is refused where it would
            # matter most.
            (("authenticator_assumed_presence",), "PASS"),
            (("mcu_stm32u5", "bootloader_devel", "authenticator_assumed_presence"),
             "PASS"),
            (("emulator", "authenticator_assumed_presence"), "PASS"),
            (("production", "authenticator_assumed_presence"),
             "assumed presence is forbidden in production"),
            (("emulator", "production", "authenticator_assumed_presence"),
             "assumed presence is forbidden in production"),
            # The ordinary hardware image. The ECCD probe matrix that used to sit
            # here is gone with the probe itself: it gated a feature that no
            # longer exists, and a guard for an absent feature is a guard that
            # can never fire.
            (("mcu_stm32u5", "bootloader_devel"), "PASS"),
        )
        with tempfile.TemporaryDirectory(prefix="auth-build-guards-") as directory:
            native = pathlib.Path(directory) / "guards.rs"
            executable = pathlib.Path(directory) / "guards"
            native.write_text(program)
            for features, expected in cases:
                with self.subTest(features=features):
                    command = ["rustc", str(native), "-o", str(executable)]
                    for feature in features:
                        command += ["--cfg", f'feature="{feature}"']
                    subprocess.run(command, check=True)
                    result = subprocess.run([str(executable)], capture_output=True, text=True)
                    self.assertEqual(result.stdout.strip(), expected)
                    self.assertEqual(result.returncode, 0 if expected == "PASS" else 2)

    def test_ordinary_storage_is_not_wired_into_the_authenticator(self):
        # Replicas 0 and 1 are STORAGE_AREAS[0] and STORAGE_AREAS[1]. Ordinary
        # storage writes both, storage_wipe() erases both, and the trezorconfig
        # module made them reachable from unprivileged MicroPython -- one import
        # away from destroying two thirds of the redundancy.
        #
        # sec/authenticator/build.rs refuses the combination outright, but that
        # guard only fires once someone re-enables the feature. These are the
        # three places the wiring actually lives, so they are pinned here: the
        # audit catches a bad artifact, this catches a bad build graph.
        embed = SOURCE.resolve().parents[2]

        # Comments are removed before the array is delimited. The prose in these
        # manifests both names the very features being asserted against and
        # contains brackets (STORAGE_AREAS[0]), either of which silently corrupts
        # a regex taken over the raw text -- the first draft of this test passed
        # for that reason rather than on merit.
        def features(manifest: pathlib.Path, name: str) -> list[str]:
            text = "\n".join(
                line
                for line in manifest.read_text().splitlines()
                if not line.lstrip().startswith("#")
            )
            start = text.index("[", text.index(f"\n{name} = [", text.index("[features]")))
            end = text.index("]", start)
            enabled = re.findall(r'"([^"]+)"', text[start:end])
            self.assertTrue(enabled, f"{manifest.name}:{name} parsed as empty")
            return enabled

        authenticator = features(embed / "projects/authenticator/Cargo.toml", "default")
        kernel = features(embed / "projects/kernel/Cargo.toml", "authenticator")
        for name, enabled in (("authenticator/default", authenticator),
                              ("kernel/authenticator", kernel)):
            with self.subTest(feature=name):
                self.assertNotIn("sec/storage", enabled)
                self.assertNotIn("trezor_lib/storage", enabled)
        # The lists are the real wiring, not an empty parse: the kernel still
        # enables the vault and the application still enables its own modules.
        self.assertIn("sec/authenticator", kernel)
        self.assertIn("upymod/authenticator", authenticator)

        # And the MicroPython door is compiled only where storage exists. The
        # guarded block is delimited by brace matching, so a later `}` in the file
        # cannot make this look satisfied.
        upymod = (embed / "upymod/build.rs").read_text()
        guard = upymod.index('if !cfg!(feature = "authenticator") {')
        depth, end = 1, upymod.index("{", guard) + 1
        while depth:
            depth += (upymod[end] == "{") - (upymod[end] == "}")
            end += 1
        self.assertIn("modtrezorconfig/modtrezorconfig.c", upymod[guard:end])
        self.assertNotIn(
            "modtrezorconfig/modtrezorconfig.c",
            upymod[:guard] + upymod[end:],
            "trezorconfig is compiled outside the non-authenticator guard",
        )

    def test_no_embedded_bootloader_and_no_way_to_install_one(self):
        # The image used to carry a compressed 128 kB bootloader that nothing
        # installed. Removing it was not housekeeping: on T3T1 the authenticator
        # must not install a bootloader at all. The model does not enable boot_ucb,
        # so boot_image_replace() takes the branch in sec/image/stm32/boot_image.c
        # that calls flash_area_erase(&BOOTLOADER_AREA) and then streams the image
        # in. Power lost in that window leaves no bootloader, on a device with no
        # screen to ask that it not be unplugged. SWD repairs that only until
        # activation step 4 raises RDP to 1, after which the sole exit is a mass
        # erase -- a recurring chance of unrecoverable failure arriving exactly
        # when recovery stops existing.
        #
        # So this pins the absence, which is easy to undo by accident: re-adding
        # the embed costs 73 KB and restores the impression that shipping firmware
        # ships a bootloader, and wiring the install re-opens the window.
        project = SOURCE.resolve().parents[0]
        embed = SOURCE.resolve().parents[2]
        source = SOURCE.read_text()

        # The comment above the removal names the very things asserted against,
        # so these run over code only. The sibling test warns about this trap for
        # TOML prose; the first draft of this one walked into it anyway. Only
        # whole-line comments are dropped, which is how every comment in build.rs
        # is written, and stripping no further keeps string literals intact.
        code = "\n".join(
            line
            for line in source.splitlines()
            if not line.lstrip().startswith("//")
        )

        self.assertNotIn(
            "embed_compressed_binary",
            code,
            "the authenticator embeds a bootloader again; see activation.md step 1",
        )
        self.assertNotIn(
            "boot_image_embdata",
            code,
            "boot_image_embdata.c is back in the source list",
        )
        self.assertFalse(
            (project / "src/stm32/boot_image_embdata.c").exists(),
            "boot_image_embdata.c exists again",
        )
        # The embeds that must remain, so this is not passing on an empty read.
        self.assertIn('lib.embed_binary(vendor_header, "vendorheader")?;', code)
        self.assertIn('lib.embed_binary(kernel, "kernel")?;', code)

        # Nothing in the project may call the install path either. Checked over
        # the real sources rather than build.rs, because the call would live in C.
        for path in sorted((project / "src").rglob("*.c")):
            text = path.read_text()
            for symbol in ("boot_image_replace", "boot_image_check",
                           "boot_image_get_embdata"):
                with self.subTest(file=path.name, symbol=symbol):
                    self.assertNotIn(
                        symbol,
                        text,
                        f"{path.name} reaches for {symbol}; "
                        "on T3T1 that erases the bootloader before writing it",
                    )

        # And the premise. If T3T1 ever gains boot_ucb the boardloader performs
        # the swap, a power cut lands either side of it, and the reasoning above
        # no longer holds -- at which point this guard should be reconsidered
        # rather than quietly satisfied, so it fails loudly instead.
        model = (embed / "models/T3T1/model.toml").read_text()
        self.assertNotIn(
            "boot_ucb",
            model,
            "T3T1 now enables boot_ucb, so bootloader replacement may be atomic; "
            "revisit this guard and activation.md step 4 instead of deleting it",
        )


if __name__ == "__main__":
    unittest.main()
