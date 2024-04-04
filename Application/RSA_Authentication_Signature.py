
import hashlib
import os
import typing
from hmac import compare_digest
from rsa import common, core, key, transform

if typing.TYPE_CHECKING:
    HashType = hashlib._Hash
else:
    HashType = typing.Any

# ASN.1 codes that describe the hash algorithm used.
HASH_ASN1 = {
    "MD5": b"\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10",
    "SHA-1": b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14",
    "SHA-224": b"\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c",
    "SHA-256": b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
    "SHA-384": b"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30",
    "SHA-512": b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40",
}

HASH_METHODS: typing.Dict[str, typing.Callable[[], HashType]] = {
    "MD5": hashlib.md5,
    "SHA-1": hashlib.sha1,
    "SHA-224": hashlib.sha224,
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
    "SHA-512": hashlib.sha512,
}


def _pad_for_encryption(message, target_length):

    max_msglength = target_length - 11
    msglength = len(message)

    if msglength > max_msglength:
        return "%i bytes needed for message, but there is only space for %i" % (msglength, max_msglength)


    # Get random padding
    padding = b""
    padding_length = target_length - msglength - 3

    while len(padding) < padding_length:
        needed_bytes = padding_length - len(padding)

        new_padding = os.urandom(needed_bytes + 5)
        new_padding = new_padding.replace(b"\x00", b"")
        padding = padding + new_padding[:needed_bytes]

    assert len(padding) == padding_length

    return b"".join([b"\x00\x02", padding, b"\x00", message])


def _pad_for_signing(message, target_length):

    max_msglength = target_length - 11
    msglength = len(message)

    if msglength > max_msglength:
        return "%i bytes needed for message, but there is only space for %i" % (msglength, max_msglength)

    padding_length = target_length - msglength - 3

    return b"".join([b"\x00\x01", padding_length * b"\xff", b"\x00", message])


def encrypt(message, pub_key):

    keylength = common.byte_size(pub_key.n)
    padded = _pad_for_encryption(message, keylength)

    payload = transform.bytes2int(padded)
    encrypted = core.encrypt_int(payload, pub_key.e, pub_key.n)
    block = transform.int2bytes(encrypted, keylength)

    return block


def decrypt(crypto, priv_key):

    blocksize = common.byte_size(priv_key.n)
    encrypted = transform.bytes2int(crypto)
    decrypted = priv_key.blinded_decrypt(encrypted)
    cleartext = transform.int2bytes(decrypted, blocksize)

    if len(crypto) > blocksize:
        # This is operating on public information, so doesn't need to be constant-time.
        return "Decryption failed"

    # If we can't find the cleartext marker, decryption failed.
    cleartext_marker_bad = not compare_digest(cleartext[:2], b"\x00\x02")

    # Find the 00 separator between the padding and the message
    sep_idx = cleartext.find(b"\x00", 2)

    sep_idx_bad = sep_idx < 10

    anything_bad = cleartext_marker_bad | sep_idx_bad
    if anything_bad:
        return "Decryption failed"

    return cleartext[sep_idx + 1 :]


def sign_hash(hash_value, priv_key, hash_method):

    # Get the ASN1 code for this hash method
    if hash_method not in HASH_ASN1:
        return "Invalid hash method: %s" % hash_method
    asn1code = HASH_ASN1[hash_method]

    # Encrypt the hash with the private key
    cleartext = asn1code + hash_value
    keylength = common.byte_size(priv_key.n)
    padded = _pad_for_signing(cleartext, keylength)

    payload = transform.bytes2int(padded)
    encrypted = priv_key.blinded_encrypt(payload)
    block = transform.int2bytes(encrypted, keylength)

    return block


def sign(message, priv_key, hash_method):

    msg_hash = compute_hash(message, hash_method)
    return sign_hash(msg_hash, priv_key, hash_method)


def verify(message, signature, pub_key):

    keylength = common.byte_size(pub_key.n)
    encrypted = transform.bytes2int(signature)
    decrypted = core.decrypt_int(encrypted, pub_key.e, pub_key.n)
    clearsig = transform.int2bytes(decrypted, keylength)

    # Get the hash method
    method_name = _find_method_hash(clearsig)
    message_hash = compute_hash(message, method_name)

    # Reconstruct the expected padded hash
    cleartext = HASH_ASN1[method_name] + message_hash
    expected = _pad_for_signing(cleartext, keylength)

    if len(signature) != keylength:
        return "Verification failed"

    # Compare with the signed one
    if expected != clearsig:
        return "Verification failed"

    return method_name


def yield_fixedblocks(infile, blocksize):

    while True:
        block = infile.read(blocksize)

        read_bytes = len(block)
        if read_bytes == 0:
            break

        yield block

        if read_bytes < blocksize:
            break


def compute_hash(message, method_name):

    if method_name not in HASH_METHODS:
        return "Invalid hash method: %s" % method_name

    method = HASH_METHODS[method_name]
    hasher = method()

    if isinstance(message, bytes):
        hasher.update(message)
    else:
        assert hasattr(message, "read") and hasattr(message.read, "__call__")
        # read as 1K blocks
        for block in yield_fixedblocks(message, 1024):
            hasher.update(block)

    return hasher.digest()


def _find_method_hash(clearsig):

    for (hashname, asn1code) in HASH_ASN1.items():
        if asn1code in clearsig:
            return hashname

    return "Verification failed"


__all__ = [
    "encrypt",
    "decrypt",
    "sign",
    "verify"
]

# sign and verify
n = 512
pub_key, priv_key = key.newkeys(n)
message_list = [b"hello world", b"John Doe 1234", b"RSA_Signature"]
for message in message_list:
    signature = sign(message, priv_key, "SHA-1")
    assert verify(message, signature, pub_key) == "SHA-1", "sign and verify failed"
    print("sign and verify passed")
