"""Readable names for stored credentials, decided on the host.

This is deliberately not in the firmware. Classification affects no key, no
authorization and no binding -- the plan that asked for it says so itself -- and a
display-free device has nowhere to show a label. The frozen module allowlist in
audit_image.py is exact, so putting a cosmetic module inside the image would widen
the audited surface of a security device for something nothing on it can read.
credentialManagement already hands a host the relying-party id, the relying-party
name, and the user's name and display name, which is everything a label needs.

What a label is for: letting the person holding the key read a list of what is on
it. What it is not: evidence about who the credential belongs to. That evidence is
the relying-party id, which the platform bound at creation time and which no
website gets to choose for another. Everything here is arranged so a label can
never be mistaken for that evidence.
"""

import unicodedata

PASSKEYS = "passkeys"
SSH = "ssh"
AWS = "aws"

# OpenSSH names its credentials with an application string rather than a domain,
# and uses "ssh:" unless told otherwise. There is no ambiguity to resolve: a
# WebAuthn relying-party id is a domain, and a domain cannot contain a colon, so
# nothing a website can register will ever land here.
SSH_PREFIX = "ssh:"

# Registrable suffixes AWS signs in under, from its own documentation: the console
# at signin.aws.amazon.com, the IAM Identity Center access portal at
# <subdomain>.awsapps.com/start, and the dual-stack portal form
# <instance>.portal.<region>.app.aws.
#
# Deliberately a short list of things that have been read rather than a guess at
# what AWS might use. An unrecognised AWS-looking domain is reported as a passkey,
# because a label that guesses is worse than a label that says less.
AWS_SUFFIXES = (
    "amazonaws.com",
    "aws.amazon.com",
    "awsapps.com",
    "app.aws",
)

# Long enough to tell accounts apart, short enough that a list stays readable.
# The relying-party id is never truncated: it is the identity, and two different
# identities must not be able to look the same after shortening.
NAME_LIMIT = 32


def _suffix_match(rp_id: str, suffix: str) -> bool:
    """True when rp_id is the suffix or sits under it, on a label boundary.

    The boundary is the whole point. Without it "not-awsapps.com" matches
    "awsapps.com", and anyone could buy a domain that reads as AWS in the list.
    """
    return rp_id == suffix or rp_id.endswith("." + suffix)


def classify_public_metadata(rp_id) -> str:
    """Which family a credential belongs to, from its relying-party id alone.

    Only the id is consulted. The relying-party *name* is chosen by the website
    and would let any site classify itself as anything; the id is the one field a
    platform binds and refuses to let a site lie about.
    """
    if not isinstance(rp_id, str) or not rp_id:
        return PASSKEYS
    if rp_id.startswith(SSH_PREFIX):
        return SSH
    folded = rp_id.strip().rstrip(".").lower()
    for suffix in AWS_SUFFIXES:
        if _suffix_match(folded, suffix):
            return AWS
    return PASSKEYS


def _sanitise(text, limit=None) -> str:
    """Strip anything that could forge structure, then bound the length.

    Removed by Unicode category rather than by a list of known-bad characters:
    control and format categories cover the bidirectional overrides and the
    zero-width joiners that make one string render as another, and surrogates and
    unassigned code points have no business in a label at all.
    """
    if not isinstance(text, str):
        return ""
    kept = []
    for character in text:
        category = unicodedata.category(character)
        if character.isspace():
            # Whitespace becomes a space rather than disappearing. A tab renders
            # as a gap, so dropping it would join two words into a third, and
            # "ad<tab>min" reading as "admin" is a forgery rather than a tidy-up.
            kept.append(" ")
            continue
        if category in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"):
            # What is left here renders as nothing at all: the remaining controls,
            # the bidirectional overrides, the zero-width joiners. Removing them
            # makes a stored label read the way it is displayed, which is the only
            # way a person can compare two of them.
            continue
        kept.append(character)
    collapsed = " ".join("".join(kept).split())
    if limit is not None and len(collapsed) > limit:
        collapsed = collapsed[:limit].rstrip()
    return collapsed


def public_label(credential) -> str:
    """One line naming a stored credential, safe to print beside others.

    Shape: the relying-party id, then the user's name in parentheses when there is
    one. The relying-party *name* is deliberately absent. A site picks its own
    name, so printing it next to the id is an invitation to register
    "Google Account" at evil.example and have it read as Google in a list -- which
    is the confusion a label is supposed to remove, not create.
    """
    if hasattr(credential, "get"):
        read = credential.get
    else:
        read = lambda key, default=None: getattr(credential, key, default)
    rp_id = _sanitise(read("rp_id", ""))
    if not rp_id:
        # Nothing identifies this credential, and inventing something would be
        # worse than admitting it.
        return "unidentified credential"
    name = _sanitise(read("user_name", ""), NAME_LIMIT)
    if not name:
        name = _sanitise(read("user_display_name", ""), NAME_LIMIT)
    return "%s (%s)" % (rp_id, name) if name else rp_id


def describe(credential) -> str:
    """Label prefixed with its family, for a flat listing."""
    family = classify_public_metadata(
        credential.get("rp_id", "") if hasattr(credential, "get")
        else getattr(credential, "rp_id", "")
    )
    return "[%s] %s" % (family, public_label(credential))
