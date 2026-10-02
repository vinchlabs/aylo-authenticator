"""Operation-specific native resident access; no generic keys or secret reads."""


def get(index):
    import trezorauth
    return trezorauth.resident_get(index)


def set(index, identifier, rp_hash):
    import trezorauth
    return trezorauth.resident_set(index, identifier, rp_hash)


def delete(index):
    import trezorauth
    return trezorauth.resident_delete(index)


def scan(rp_hash=None):
    import trezorauth
    return trezorauth.resident_scan(rp_hash)
