"""Executed in the dedicated real MicroPython emulator, never with auth mocks."""
import trezorauth as auth
from trezorcrypto import aes, sha256
from apps.authenticator.credential import Credential, CredentialUnavailable, CredentialLimitExceeded
from apps.authenticator.resident_store import ResidentStore

PIN=b"\x01"+bytes(15)
PEER=bytes.fromhex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")

def invalid(call):
    try:
        call()
    except (ValueError,TypeError):
        return
    raise AssertionError("invalid argument accepted")

for name in ("credential_create","credential_open","credential_sign","credential_hmac_secret",
             "resident_get","resident_set","resident_delete"):
    assert hasattr(auth,name)
for name in ("root","private_key","derive","read_secret","hmac_secret_key"):
    assert not hasattr(auth,name)
invalid(lambda:auth.credential_create(bytes(32),-9,b"metadata"))
invalid(lambda:auth.credential_sign(bytes(89),bytes(32),2**200,b"m"))
invalid(lambda:auth.resident_get(100))
invalid(lambda:auth.resident_set(-1,bytes(89),bytes(32)))
invalid(lambda:auth.resident_delete(2**200))

if getattr(auth,"TEST_BACKEND",False):
    assert auth.wipe()==auth.OK
    assert auth.provision(PIN)==auth.OK
    # MC/GA require an RP binding; credential-management-only permits no RP.
    from trezor.crypto import hashlib
    rp=hashlib.sha256(b"example.com").digest()
    def unlock(permission=7, bound=True):
        # The PIN hash reaches the vault encrypted under the shared secret, so it
        # has to be sealed here too. The peer key is P-256's base point, which
        # makes the point the vault derives exactly the public key it just handed
        # over -- no platform private key is needed to encrypt for it. The PIN
        # protocols themselves are covered in test_trezorauth.py; this is only
        # the way in to the credential surface under test.
        result,public=auth.key_agreement()
        assert result==auth.OK
        sealed=aes(aes.CBC,sha256(public[1:33]).digest(),bytes(16)).encrypt(PIN)
        assert auth.issue_token(sealed,1,permission,rp if bound else None,PEER)[0]==auth.OK
    for algorithm in (-7,-8):
        unlock(1)
        credential=Credential.create("example.com",b"user",user_name="name",algorithm=algorithm,hmac_secret=True)
        assert credential.cred_protect==3 and credential.user_id==b"user"
        assert len(credential.public_key())==(77 if algorithm==-7 else 42)
        ResidentStore.set(99,credential)
        unlock(2)
        assert ResidentStore.get(99).id==credential.id
        opened=Credential.open(credential.id,rp)
        assert opened.public_key()==credential.public_key()
        assert opened.user_name=="name"
        signature=credential.sign(b"message")
        assert (8<=len(signature)<=72) if algorithm==-7 else len(signature)==64
        output=credential.hmac_secret(bytes(32),bytes(32))
        assert len(output)==64 and output[:32]==output[32:]
        assert len(credential.hmac_secret(bytes(32)))==32
        unlock(4,False)
        assert [(i,c.id) for i,c in ResidentStore.enumerate()]==[(99,credential.id)]
        try:
            ResidentStore.set(98,credential)
        except CredentialUnavailable:
            pass
        else:
            raise AssertionError("duplicate credential accepted")
        unlock(4,False)
        ResidentStore.delete(99)
        assert list(ResidentStore.enumerate())==[]
    # Mixed-RP discovery skips a foreign slot without erasing the GA token.
    rp=hashlib.sha256(b"example.com").digest()
    unlock(1)
    original=Credential.create("example.com",b"one",algorithm=-7)
    ResidentStore.set(99,original)
    rp=hashlib.sha256(b"another.com").digest()
    unlock(1)
    foreign=Credential.create("another.com",b"two",algorithm=-8)
    ResidentStore.set(0,foreign)
    try:
        ResidentStore.set(0,foreign)
    except CredentialUnavailable:
        pass
    else:
        raise AssertionError("MC token replaced an occupied slot")
    rp=original.rp_id_hash
    unlock(2)
    assert ResidentStore.get(0) is None
    assert [(i,c.id) for i,c in ResidentStore.enumerate()]==[(99,original.id)]
    assert original.sign(b"after foreign nonmatch")
    invalid(lambda:auth.issue_token(PIN,1,1,None,PEER))
    invalid(lambda:auth.issue_token(PIN,1,2,None,PEER))
    unlock(4,False)
    assert [(i,c.id) for i,c in ResidentStore.enumerate()]==[(0,foreign.id),(99,original.id)]
    ResidentStore.delete(0)
    ResidentStore.delete(99)
    rp=hashlib.sha256(b"r"*80).digest()
    unlock(1)
    large=Credential.create("r"*80,bytes(64),rp_name="r"*100,user_name="n"*100,user_display_name="d"*100)
    # Every field is within the protocol bounds, but the aggregate exceeds the
    # explicit resident v1 cap. Nonresident create/open remains available.
    unlock(2)
    assert Credential.open(large.id,rp).user_display_name=="d"*100
    unlock(1)
    try:
        ResidentStore.set(0,large)
    except CredentialLimitExceeded:
        pass
    else:
        raise AssertionError("oversized resident metadata accepted")
    unlock()
    auth.disconnect()
    try:
        Credential.open(credential.id,rp)
    except CredentialUnavailable:
        pass
    else:
        raise AssertionError("credential access survives disconnect")
else:
    assert auth.credential_open(bytes(89),bytes(32))[0]!=auth.OK
print("TREZORAUTH_CREDENTIALS_PASS")
