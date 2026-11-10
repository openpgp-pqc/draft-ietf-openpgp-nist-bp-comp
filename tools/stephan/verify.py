#!/usr/bin/env python3
"""Additional sanity check outside the OpenPGP implementation ecosystem.
No Sequoia or repository verification code used.
Usage: python3 tools/stephan/verify.py [--vectors /path/to/test-vectors]
Requires cryptography >= 50.0.0 and openssl >= 3.5.
"""

import argparse
import base64
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import zlib

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils, mldsa, mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESOCB3, AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, InvalidUnwrap


def u32(n):
    return n.to_bytes(4, "big")


def num(b):
    return int.from_bytes(b, "big")


def require(ok, why):
    if not ok:
        raise ValueError(why)


def armor(path):
    lines = pathlib.Path(path).read_text().splitlines()
    start = next(i for i, x in enumerate(lines) if x.startswith("-----BEGIN")) + 1
    while start < len(lines) and ":" in lines[start]:
        start += 1
    return base64.b64decode(
        "".join(x for x in lines[start:] if x and not x.startswith(("=", "-----"))),
        validate=True,
    )


def packets(data):
    pos = 0
    while pos < len(data):
        head = data[pos]
        pos += 1
        require(head & 0xC0 == 0xC0, "only new-format packet headers supported")
        parts = []
        while True:
            first = data[pos]
            pos += 1
            partial = False
            if first < 192:
                length = first
            elif first < 224:
                length = ((first - 192) << 8) + data[pos] + 192
                pos += 1
            elif first == 255:
                length = num(data[pos : pos + 4])
                pos += 4
            else:
                length = 1 << (first & 31)
                partial = True
            require(pos + length <= len(data), "truncated packet")
            parts.append(data[pos : pos + length])
            pos += length
            if not partial:
                break
        yield head & 63, b"".join(parts)


# Curve, scalar length, ML-DSA public-key length, ML-DSA signature length, class.
SUITES = {
    41: (ec.SECP384R1, 48, 1952, 3309, mldsa.MLDSA65PublicKey),
    42: (ec.SECP521R1, 66, 2592, 4627, mldsa.MLDSA87PublicKey),
    43: (ec.BrainpoolP384R1, 48, 1952, 3309, mldsa.MLDSA65PublicKey),
    44: (ec.BrainpoolP512R1, 64, 2592, 4627, mldsa.MLDSA87PublicKey),
}
HASHES = {
    9: ("sha384", hashes.SHA384, 24),
    10: ("sha512", hashes.SHA512, 32),
    14: ("sha3_512", hashes.SHA3_512, 32),
}
# ML-KEM public-key length, ciphertext length, seed import class.
KEMS = {
    37: (1184, 1088, mlkem.MLKEM768PrivateKey),
    38: (1568, 1568, mlkem.MLKEM1024PrivateKey),
    39: (1184, 1088, mlkem.MLKEM768PrivateKey),
    40: (1568, 1568, mlkem.MLKEM1024PrivateKey),
}


def public_part(body):
    require(body[0] == 6, "key must be v6")
    # v6: version (1), creation time (4), algorithm (1), public-material length (4).
    end = 10 + num(body[6:10])
    require(end <= len(body), "truncated public key")
    return body[:end]


def framed_key(body):
    body = public_part(body)
    return b"\x9b" + u32(len(body)) + body


def keys(body):
    body = public_part(body)
    alg = body[5]
    curve, n, pklen, _, cls = SUITES[alg]
    point = body[10 : 11 + 2 * n]
    pq = body[11 + 2 * n :]
    require(len(pq) == pklen, "ML-DSA public key length")
    return ec.EllipticCurvePublicKey.from_encoded_point(
        curve(), point
    ), cls.from_public_bytes(pq)


def reject(call):
    try:
        call()
    except InvalidSignature:
        return
    raise ValueError("modified input was accepted")


def verify(sig, data, primary, label, openssl):
    require(sig[0] == 6 and sig[2] == primary[5], "signature version/algorithm")
    hname, hcls, saltlen = HASHES[sig[3]]
    end = 8 + num(sig[4:8])
    header = sig[:end]
    pos = end + 4 + num(sig[end : end + 4])
    prefix = sig[pos : pos + 2]
    pos += 2
    sl = sig[pos]
    pos += 1
    require(sl == saltlen, "salt size")
    salt = sig[pos : pos + sl]
    material = sig[pos + sl :]
    # RFC 9580 5.2.4: salt || signed data || hashed signature header || trailer.
    # The trailer counts only the signature header, not the salt or signed data.
    digest = hashlib.new(
        hname, salt + data + header + b"\x06\xff" + u32(len(header))
    ).digest()
    require(digest[:2] == prefix, "v6 digest prefix mismatch")
    _, n, _, siglen, _ = SUITES[sig[2]]
    require(len(material) == 2 * n + siglen, "signature material length")
    der = utils.encode_dss_signature(num(material[:n]), num(material[n : 2 * n]))
    pqsig = material[2 * n :]
    classical, pq = keys(primary)
    classical.verify(der, digest, ec.ECDSA(utils.Prehashed(hcls())))
    pq.verify(pqsig, digest, context=b"")
    # A second invocation through system OpenSSL, using the same extracted
    # public key, digest and signature, with pure ML-DSA and empty context.
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        (td / "key.der").write_bytes(
            pq.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        (td / "signature").write_bytes(pqsig)
        (td / "digest").write_bytes(digest)
        r = subprocess.run(
            [
                openssl,
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(td / "key.der"),
                "-rawin",
                "-in",
                str(td / "digest"),
                "-sigfile",
                str(td / "signature"),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        require(r.returncode == 0, "OpenSSL ML-DSA: " + r.stdout + r.stderr)
    altered = bytes([digest[0] ^ 1]) + digest[1:]
    reject(lambda: classical.verify(der, altered, ec.ECDSA(utils.Prehashed(hcls()))))
    reject(lambda: pq.verify(pqsig, altered, context=b""))
    damaged = bytes([pqsig[0] ^ 1]) + pqsig[1:]
    reject(lambda: pq.verify(damaged, digest, context=b""))
    reject(lambda: pq.verify(pqsig, digest, context=b"wrong"))
    print(
        f"PASS suite={sig[2]} {label}: {hname} prefix={prefix.hex()} ECDSA / ML-DSA / OpenSSL-ML-DSA; negative controls rejected"
    )
    return {
        "suite": sig[2],
        "kind": label,
        "hash": hname,
        "digest": digest.hex(),
        "signature_sha256": hashlib.sha256(sig).hexdigest(),
        "ecdsa": True,
        "mldsa": True,
        "openssl_mldsa": True,
        "negative_controls": 4,
    }


def combine(mlkem_share, ecdh_share, ephemeral, recipient, alg):
    # RFC 9980 4.2.1; the final byte makes the domain separator suffix-free.
    domain = b"OpenPGPCompositeKDFv1"
    return hashlib.sha3_256(
        mlkem_share
        + ecdh_share
        + ephemeral
        + recipient
        + bytes([alg])
        + domain
        + bytes([len(domain)])
    ).digest()


def establish_session(pkesk, secret_subkey, openssl):
    public = public_part(secret_subkey)
    alg = public[5]
    curve, n, _, _, _ = SUITES[alg + 4]
    pklen, ctlen, cls = KEMS[alg]
    pointlen = 1 + 2 * n
    require(len(public) == 10 + pointlen + pklen, "KEM public material length")
    recipient = public[10 : 10 + pointlen]
    mlkem_public = public[10 + pointlen :]
    secret = secret_subkey[len(public) :]
    # The published v6 secret subkeys are unencrypted: usage 0, scalar, d || z.
    require(
        len(secret) == 1 + n + 64 and secret[0] == 0,
        "expected unencrypted v6 KEM secret material",
    )
    classical = ec.derive_private_key(num(secret[1 : 1 + n]), curve())
    recipient_key = ec.EllipticCurvePublicKey.from_encoded_point(curve(), recipient)
    require(
        classical.public_key().public_numbers() == recipient_key.public_numbers(),
        "ECDH private/public key mismatch",
    )
    pq = cls.from_seed_bytes(secret[1 + n :])
    require(
        pq.public_key().public_bytes_raw() == mlkem_public,
        "ML-KEM seed-derived public key mismatch",
    )

    # These vectors use a v6 recipient field with a v6, 32-byte fingerprint.
    require(pkesk[:3] == b"\x06\x21\x06", "expected v6 PKESK recipient")
    fingerprint = hashlib.sha256(framed_key(public)).digest()
    require(
        pkesk[3:35] == fingerprint and pkesk[35] == alg,
        "PKESK recipient fingerprint/algorithm mismatch",
    )
    pos = 36
    ephemeral = pkesk[pos : pos + pointlen]
    pos += pointlen
    ciphertext = pkesk[pos : pos + ctlen]
    pos += ctlen
    require(
        pos < len(pkesk) and pkesk[pos] == len(pkesk) - pos - 1,
        "wrapped session key length",
    )
    wrapped = pkesk[pos + 1 :]
    ephemeral_key = ec.EllipticCurvePublicKey.from_encoded_point(curve(), ephemeral)
    ecdh_share = classical.exchange(ec.ECDH(), ephemeral_key)
    mlkem_share = pq.decapsulate(ciphertext)
    require(len(ecdh_share) == n and len(mlkem_share) == 32, "KEM share lengths")

    # Repeat ML-KEM decapsulation through system OpenSSL, from the same seed.
    # Only public test-vector keys are written; TemporaryDirectory cleans up.
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        (td / "key.der").write_bytes(
            pq.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        (td / "ciphertext").write_bytes(ciphertext)
        r = subprocess.run(
            [
                openssl,
                "pkeyutl",
                "-decap",
                "-inkey",
                str(td / "key.der"),
                "-in",
                str(td / "ciphertext"),
                "-out",
                str(td / "share"),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        require(r.returncode == 0, "OpenSSL ML-KEM: " + r.stdout + r.stderr)
        require(
            (td / "share").read_bytes() == mlkem_share,
            "Python/system OpenSSL ML-KEM share mismatch",
        )

    kek = combine(mlkem_share, ecdh_share, ephemeral, recipient, alg)
    session = aes_key_unwrap(kek, wrapped)
    require(len(session) == 32, "expected AES-256 session key")
    # ML-KEM implicitly rejects invalid ciphertexts by returning another share.
    changed = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    rejected_share = pq.decapsulate(changed)
    require(rejected_share != mlkem_share, "modified ML-KEM ciphertext kept share")
    bad_kek = combine(rejected_share, ecdh_share, ephemeral, recipient, alg)
    try:
        aes_key_unwrap(bad_kek, wrapped)
    except InvalidUnwrap:
        pass
    else:
        raise ValueError("modified ML-KEM ciphertext unwrapped session key")
    values = {
        "recipient": fingerprint.hex(),
        "mlkemKeyShare": mlkem_share.hex(),
        "ecdhKeyShare": ecdh_share.hex(),
        "multiKeyCombine": kek.hex(),
        "sessionKey": session.hex(),
    }
    print(
        f"PASS KEM={alg} ML-KEM / OpenSSL-ML-KEM / ECDH / SHA3-256 combiner / AES unwrap; modified ciphertext rejected"
    )
    return session, values


def decrypt(body, session):
    require(body[0] == 2 and body[1] == 9, "expected SEIPDv2 AES-256")
    mode = body[2]
    size = 1 << (body[3] + 6)
    info = b"\xd2" + body[:4]
    cls, noncelen = {2: (AESOCB3, 15), 3: (AESGCM, 12)}[mode]
    material = HKDF(
        algorithm=hashes.SHA256(), length=32 + noncelen - 8, salt=body[4:36], info=info
    ).derive(session)
    aead = cls(material[:32])
    iv = material[32:]
    encrypted = body[36:-16]
    final = body[-16:]
    chunks = []
    index = 0
    while encrypted:
        count = min(size + 16, len(encrypted))
        chunk = encrypted[:count]
        encrypted = encrypted[count:]
        chunks.append(aead.decrypt(iv + index.to_bytes(8, "big"), chunk, info))
        index += 1
    result = b"".join(chunks)
    require(
        aead.decrypt(
            iv + index.to_bytes(8, "big"), final, info + len(result).to_bytes(8, "big")
        )
        == b"",
        "summary tag",
    )
    return result


def flatten(data):
    for tag, body in packets(data):
        if tag == 8:
            algorithm = body[0]
            decompressed = {
                0: lambda x: x,
                1: lambda x: zlib.decompress(x, -15),
                2: zlib.decompress,
            }[algorithm](body[1:])
            yield from flatten(decompressed)
        else:
            yield tag, body


def main(args):
    root = args.vectors.resolve()
    results = []
    inventory = {}
    kem_results = {}
    print("Vectors:", root)
    openssl_version = subprocess.check_output(
        [args.openssl, "version"], text=True, timeout=30
    ).strip()
    print(openssl_version)
    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend

    print("cryptography", cryptography.__version__, backend.openssl_version_text())
    for alg in SUITES:
        kem = alg - 4
        certs = []
        for name in ("pubkey", "seckey"):
            path = root / f"{name}-primary{alg}-sub{kem}.asc"
            cert = list(packets(armor(path)))
            certs.append(cert)
            primary = public_part(cert[0][1])
            sub = None
            uid = None
            for tag, body in cert:
                if tag == 13:
                    uid = body
                elif tag in (7, 14):
                    sub = public_part(body)
                elif tag == 2:
                    st = body[1]
                    data = framed_key(primary)
                    if st == 0x1F:
                        label = "direct-key"
                    elif st in range(0x10, 0x14):
                        require(uid is not None, "missing user ID")
                        data += b"\xb4" + u32(len(uid)) + uid
                        label = "user-ID certification"
                    elif st == 0x18:
                        require(sub is not None, "missing subkey")
                        data += framed_key(sub)
                        label = "subkey binding"
                    else:
                        raise ValueError(f"unhandled certificate signature {st}")
                    results.append(
                        verify(body, data, primary, name + " " + label, args.openssl)
                    )
        pub, sec = certs
        require(
            [(t, public_part(b) if t in (5, 7) else b) for t, b in sec]
            == [(5 if t == 6 else 7 if t == 14 else t, b) for t, b in pub],
            "public and secret certificate differ",
        )
        primary = pub[0][1]
        msg = (root / "Testing.txt").read_bytes()
        detached = list(packets(armor(root / f"detached-alg{alg}.asc")))
        require(
            len(detached) == 1 and detached[0][0] == 2 and detached[0][1][1] == 0,
            "expected binary detached signature",
        )
        results.append(verify(detached[0][1], msg, primary, "detached", args.openssl))
        encrypted = list(
            packets(armor(root / f"encrypted-alg{kem}_signed-alg{alg}.asc"))
        )
        require([t for t, b in encrypted] == [1, 18], "expected PKESK and SEIPD")
        subkeys = [b for t, b in sec if t == 7]
        require(len(subkeys) == 1 and subkeys[0][5] == kem, "expected KEM subkey")
        session, values = establish_session(encrypted[0][1], subkeys[0], args.openssl)
        # Metadata is only an expected-output oracle, never a decryption input.
        metadata = json.loads((root / f"metadata-alg{alg}.json").read_text())
        for field, value in values.items():
            require(
                bytes.fromhex(metadata[field]) == bytes.fromhex(value),
                f"KEM {kem} metadata mismatch: {field}",
            )
        kem_results[str(kem)] = values
        plain = decrypt(encrypted[1][1], session)
        inside = list(flatten(plain))
        print(
            f"PASS suite={alg} SEIPDv2 chunk and final authentication; inner packets={[t for t,b in inside]} (independently recovered session key)"
        )
        literal = [b for t, b in inside if t == 11]
        sigs = [b for t, b in inside if t == 2]
        require(len(literal) == 1 and len(sigs) == 1, "literal/signature count")
        body = literal[0]
        payload = body[6 + body[1] :]
        require(payload == msg, "decrypted payload differs")
        require(sigs[0][1] == 0, "expected binary inline signature")
        results.append(
            verify(sigs[0], payload, primary, "encrypted inline", args.openssl)
        )
        # Verify all signature packet occurrences in certificates and messages
        # are accounted for; pubkey and seckey carry duplicate signatures.
        require(
            sum(t == 2 for t, b in pub) == 3 and sum(t == 2 for t, b in sec) == 3,
            "certificate signature count",
        )
        inventory[str(alg)] = {
            "certificate_signatures": 3,
            "detached_signatures": 1,
            "inline_signatures": 1,
            "authenticated_decryption": True,
            "kem_key_establishment": True,
        }
    require(len(results) == 32, "expected 32 signature occurrences")
    unique = {r["signature_sha256"] for r in results}
    require(len(unique) == 20, "expected 20 unique signatures")
    print(
        f"ALL PASS: {len(results)} occurrences, {len(unique)} unique composite signatures, 4 hybrid KEM chains, 4 authenticated encrypted messages."
    )
    if args.output is not None:
        inputs = {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.iterdir())
            if p.is_file() and p.suffix in (".asc", ".json", ".txt")
        }
        report = {
            "results": results,
            "inventory": inventory,
            "kem_results": kem_results,
            "vectors": str(root),
            "input_sha256": inputs,
            "runtime": {
                "cryptography": cryptography.__version__,
                "cryptography_openssl": backend.openssl_version_text(),
                "system_openssl": openssl_version,
            },
            "scope": {
                "kem_checked": True,
                "decryption_key_source": "ML-KEM + ECDH, composite combiner, AES key unwrap",
                "purpose": "additional sanity check outside the OpenPGP implementation ecosystem",
                "unique_signatures": len(unique),
                "signature_occurrences": len(results),
            },
        }
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print("Report:", args.output)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--vectors",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[2] / "test-vectors",
        help="vector directory (default: this checkout's test-vectors/, independent of working directory)",
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        help="write JSON results and input checksums to this file; otherwise only print results",
    )
    parser.add_argument(
        "--openssl",
        default="openssl",
        help="OpenSSL executable with ML-DSA and ML-KEM support (default: openssl on PATH)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    try:
        main(parse_args())
    except (
        OSError,
        ValueError,
        KeyError,
        IndexError,
        InvalidSignature,
        InvalidTag,
        InvalidUnwrap,
        UnsupportedAlgorithm,
        StopIteration,
        subprocess.SubprocessError,
    ) as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
