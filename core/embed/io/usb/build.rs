use xbuild::{CLibrary, Result, bail_unsupported};

#[path = "../../projects/authenticator/tools/usb_allocation.rs"]
mod usb_allocation;

pub fn def_module(lib: &mut CLibrary) -> Result<()> {
    lib.add_include("usb/inc");

    lib.add_define("USE_USB", Some("1"));

    if cfg!(feature = "authenticator") {
        lib.add_define("AUTHENTICATOR", Some("1"));
        // Announced before the decision below, not inside it. Cargo only reruns a
        // build script for a variable the previous run told it about, and the branch
        // that reads these two is not taken unless they are already set -- so
        // declaring them there means the first build after setting them reuses the
        // cached result and ignores the identity without saying so. Measured: a build
        // with both set succeeded and produced an image still carrying 1209:53C1,
        // until the script was forced to rerun.
        println!("cargo:rerun-if-env-changed=AUTHENTICATOR_USB_VID");
        println!("cargo:rerun-if-env-changed=AUTHENTICATOR_USB_PID");
        // A development build may carry an allocated identity too, and supplying one
        // is the only way to stop a host naming this device after someone else:
        // 1209:53C1 is Trezor's allocation under pid.codes, so any operating system
        // with a USB id database resolves it to Trezor's product name whatever
        // strings this firmware reports.
        //
        // The pair goes through approved_identity() either way, so it still has to
        // be four hex digits, not reserved, not the development pair, and present in
        // the reviewed allocation list. This adds a use for an allocation; it is not
        // a way around the review. What stays development is the build, not the
        // identity: the image still reports AUTH-DEV and the audit still refuses to
        // certify it as production.
        let supplied = std::env::var_os("AUTHENTICATOR_USB_VID").is_some()
            || std::env::var_os("AUTHENTICATOR_USB_PID").is_some();
        if cfg!(feature = "production") || supplied {
            let (vid, pid) = usb_allocation::approved_identity()?;
            lib.add_define("AUTHENTICATOR_USB_VID", Some(&format!("0x{vid:04x}")));
            lib.add_define("AUTHENTICATOR_USB_PID", Some(&format!("0x{pid:04x}")));
        }
    }

    if cfg!(feature = "usb_iface_wire") {
        lib.add_define("USE_USB_IFACE_WIRE", Some("1"));
    }

    if cfg!(feature = "usb_iface_debug") {
        lib.add_define("USE_USB_IFACE_DEBUG", Some("1"));
        lib.add_define("DEBUGLINK", Some("1"));
    }

    if cfg!(feature = "usb_iface_webauthn") {
        lib.add_define("USE_USB_IFACE_WEBAUTHN", Some("1"));
    }

    if cfg!(feature = "usb_iface_vcp") {
        lib.add_define("USE_USB_IFACE_VCP", Some("1"));
    }

    if cfg!(feature = "emulator") {
        lib.add_sources(["usb/unix/sock.c", "usb/unix/usb.c", "usb/usb_config.c"]);
    } else if cfg!(feature = "mcu_stm32") {
        lib.add_sources([
            "usb/stm32/usb_class_hid.c",
            "usb/stm32/usb_class_vcp.c",
            "usb/stm32/usb_class_webusb.c",
            "usb/stm32/usb.c",
            "usb/stm32/usb_rbuf.c",
            "usb/stm32/usbd_conf.c",
            "usb/stm32/usbd_core.c",
            "usb/stm32/usbd_ctlreq.c",
            "usb/stm32/usbd_ioreq.c",
            "usb/usb_config.c",
        ]);
    } else {
        bail_unsupported!();
    }

    Ok(())
}
