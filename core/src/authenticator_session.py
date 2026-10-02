"""Start only the WebAuthn HID service."""


def run() -> None:
    import trezorio

    from apps.authenticator import boot

    bus = trezorio.USB()
    iface = trezorio.USBIF(handle=trezorio.USBIF_WEBAUTHN)
    bus.open("AUTH-DEV000000000000000000")
    boot(iface)
