"""Display-free authenticator transport. Sensitive commands remain disabled."""


def boot(iface) -> None:
    from trezor import loop

    from .transport import handle_reports

    loop.run(handle_reports(iface))
