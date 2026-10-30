"""Decoy credential derivation: derive(), SSH keys, kubeconfig tokens, OWNER."""

import base64
import functools
import hashlib
import struct

from . import ed25519
from .common import beneath, canonical_path, hmac_sha256, sha256_hex

TOKEN_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
DERIVED_FORMATS = ("ssh-ed25519", "kubeconfig-token")
FORMATS = ("aws-access-key", "ssh-ed25519", "kubeconfig-token")


def derive(seed, deployment_id, epoch, decoy_id, label):
    message = "%s\n%d\n%s\n%s" % (deployment_id, epoch, decoy_id, label)
    return hmac_sha256(seed.encode("utf-8"), message.encode("utf-8"))


def layout_byte(seed, deployment_id, decoy_id):
    message = "%s\nlayout\n%s" % (deployment_id, decoy_id)
    return hmac_sha256(seed.encode("utf-8"), message.encode("utf-8"))[0]


def ssh_key(seed, deployment_id, epoch, decoy_id):
    """Return (private_key_seed_hex, blob_base64, fingerprint)."""
    private = derive(seed, deployment_id, epoch, decoy_id, "ed25519")
    public = ed25519.public_key(private)
    blob = (struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + public)
    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return private.hex(), base64.b64encode(blob).decode("ascii"), fingerprint


def kube_token(seed, deployment_id, epoch, decoy_id):
    raw = derive(seed, deployment_id, epoch, decoy_id, "token")[:22]
    text = "".join(TOKEN_ALPHABET[b % 36] for b in raw)
    return text[:6] + "." + text[6:]


def identifier(seed, deployment_id, epoch, decoy_id, credential_format):
    if credential_format == "ssh-ed25519":
        return ssh_key(seed, deployment_id, epoch, decoy_id)[2]
    assert credential_format == "kubeconfig-token", "identifier needs a derived format"
    return kube_token(seed, deployment_id, epoch, decoy_id)


@functools.lru_cache(maxsize=4096)
def identifier_digest(seed, deployment_id, epoch, decoy_id, credential_format):
    return sha256_hex(identifier(seed, deployment_id, epoch, decoy_id,
                                 credential_format))


def owner(canonical_location, aliases, dormant_user):
    """The account a real file at that canonical location would belong to."""
    if beneath(canonical_location, canonical_path("/root", aliases)):
        return "root"
    names = []
    home = canonical_path("/home", aliases)
    if beneath(canonical_location, home):
        rest = canonical_location[len(home):] if home != "/" else canonical_location
        names.append(rest.split("/")[1])
    for alias, _ in aliases:
        if beneath(alias, "/home"):
            names.append(alias.split("/")[2])
    for name in names:
        base = canonical_path("/home/" + name, aliases)
        if beneath(canonical_location, base):
            return name
    return dormant_user if dormant_user is not None else "root"


def companion_paths(location, credential_format):
    """Raw companion paths of a credential decoy at location."""
    if credential_format == "ssh-ed25519":
        return [location + ".pub"]
    if credential_format == "aws-access-key":
        head = location.rsplit("/", 1)[0]
        return [(head or "") + "/config"]
    return []

