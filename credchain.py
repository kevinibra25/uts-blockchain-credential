#!/usr/bin/env python3
"""
credchain.py - Prototipe simulasi sistem verifikasi kredensial akademik berbasis
permissioned blockchain (data simulasi, berjalan lokal, tanpa jaringan).

Komponen:
  - Kredensial dengan field ber-salt (selective disclosure via Merkle proof)
  - Tanda tangan penerbit Ed25519 atas (credentialId, merkleRoot, issuerKeyId)
  - Ledger mini (hash-linked blocks) berisi registry penerbit + status kredensial
  - Verifier yang hanya membaca ledger (tidak menulis)
Hasil uji dicetak dan disimpan ke results.json.
"""
import hashlib, json, os, time, secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

H = lambda b: hashlib.sha256(b).hexdigest()


def hb(b):
    return hashlib.sha256(b).digest()


# ---------------------------------------------------------------- Merkle tree
def leaf(salt: bytes, name: str, value: str) -> bytes:
    # encoding: UTF-8, domain separation 0x00 untuk leaf
    return hb(b"\x00" + salt + name.encode() + b"=" + value.encode())


def node(l: bytes, r: bytes) -> bytes:
    return hb(b"\x01" + l + r)  # domain separation 0x01 untuk node internal


def merkle_levels(leaves):
    lv = [list(leaves)]
    while len(lv[-1]) > 1:
        cur, nxt = lv[-1], []
        for i in range(0, len(cur), 2):
            a = cur[i]
            b = cur[i + 1] if i + 1 < len(cur) else cur[i]  # duplikasi ganjil
            nxt.append(node(a, b))
        lv.append(nxt)
    return lv


def merkle_proof(levels, idx):
    proof = []
    for lvl in levels[:-1]:
        sib = idx ^ 1
        sibling = lvl[sib] if sib < len(lvl) else lvl[idx]
        proof.append((sibling.hex(), "R" if idx % 2 == 0 else "L"))
        idx //= 2
    return proof


def verify_proof(leaf_hash: bytes, proof, root: bytes) -> bool:
    cur = leaf_hash
    for sib_hex, side in proof:
        sib = bytes.fromhex(sib_hex)
        cur = node(cur, sib) if side == "R" else node(sib, cur)
    return cur == root


# ---------------------------------------------------------------- Kunci
def new_key():
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk, pk


# ---------------------------------------------------------------- Ledger
class Ledger:
    """Ledger mini: blok berantai hash. Konsensus disimulasikan (PBFT/QBFT)
    sebagai kuorum 2f+1 dari n validator; bukan implementasi protokol."""

    def __init__(self, n_validators=4):
        self.n = n_validators
        self.f = (n_validators - 1) // 3
        self.blocks = []
        self.state = {"issuers": {}, "creds": {}}  # world state
        self._append([{"type": "GENESIS"}])

    @staticmethod
    def _bhash(b):
        body = json.dumps({k: b[k] for k in ("height", "prev", "txs", "ts")},
                          sort_keys=True, separators=(",", ":")).encode()
        return H(body)

    def _append(self, txs):
        prev = self.blocks[-1]["hash"] if self.blocks else "0" * 64
        b = {"height": len(self.blocks), "prev": prev, "txs": txs,
             "ts": 1_790_000_000 + len(self.blocks)}  # timestamp simulasi tetap
        b["hash"] = self._bhash(b)
        self.blocks.append(b)
        return b

    def commit(self, tx, votes=None):
        """Commit satu transaksi bila kuorum 2f+1 setuju."""
        votes = self.n if votes is None else votes
        if votes < 2 * self.f + 1:
            raise PermissionError("kuorum tidak tercapai")
        self._apply(tx)
        return self._append([tx])

    def _apply(self, tx):
        t = tx["type"]
        S = self.state
        if t == "ADD_ISSUER":
            S["issuers"][tx["issuerId"]] = {"keys": {tx["keyId"]: {
                "pub": tx["pub"], "from": tx["ts"], "to": None}}, "active": True}
        elif t == "ROTATE_KEY":
            iss = S["issuers"][tx["issuerId"]]
            for k in iss["keys"].values():
                if k["to"] is None:
                    k["to"] = tx["ts"]
            iss["keys"][tx["keyId"]] = {"pub": tx["pub"], "from": tx["ts"], "to": None}
        elif t == "ISSUE":
            if tx["credId"] in S["creds"]:
                raise ValueError("credId sudah ada")
            iss = S["issuers"].get(tx["issuerId"])
            if not iss or not iss["active"]:
                raise PermissionError("penerbit tidak terdaftar/aktif")
            S["creds"][tx["credId"]] = {"issuerId": tx["issuerId"], "root": tx["root"],
                                         "status": "ISSUED", "keyId": tx["keyId"],
                                         "issuedAt": tx["ts"], "supersededBy": None}
        elif t in ("REVOKE", "SUSPEND", "REINSTATE", "SUPERSEDE"):
            c = S["creds"].get(tx["credId"])
            if not c:
                raise KeyError("kredensial tidak ada")
            if c["issuerId"] != tx["issuerId"]:
                raise PermissionError("hanya penerbit asli yang boleh mengubah status")
            cur = c["status"]
            ok = {("ISSUED", "REVOKE"), ("ISSUED", "SUSPEND"), ("SUSPENDED", "REINSTATE"),
                  ("SUSPENDED", "REVOKE"), ("ISSUED", "SUPERSEDE")}
            if (cur, t) not in ok:
                raise ValueError(f"transisi tidak valid: {cur} -> {t}")
            c["status"] = {"REVOKE": "REVOKED", "SUSPEND": "SUSPENDED",
                           "REINSTATE": "ISSUED", "SUPERSEDE": "SUPERSEDED"}[t]
            if t == "SUPERSEDE":
                c["supersededBy"] = tx["newCredId"]
            c["reason"] = tx.get("reason")
        elif t == "DEACTIVATE_ISSUER":
            S["issuers"][tx["issuerId"]]["active"] = False
        else:
            raise ValueError("tipe transaksi tidak dikenal")

    def validate_chain(self):
        for i, b in enumerate(self.blocks):
            if b["hash"] != self._bhash(b):
                return False, i
            if i and b["prev"] != self.blocks[i - 1]["hash"]:
                return False, i
        return True, None


# ---------------------------------------------------------------- Penerbit
class Issuer:
    def __init__(self, ledger, issuer_id, ts0):
        self.L, self.id = ledger, issuer_id
        self.sk, pub = new_key()
        self.key_id = f"{issuer_id}#key-1"
        self.L.commit({"type": "ADD_ISSUER", "issuerId": issuer_id,
                       "keyId": self.key_id, "pub": pub.hex(), "ts": ts0})

    def rotate(self, ts, n):
        self.sk, pub = new_key()
        self.key_id = f"{self.id}#key-{n}"
        self.L.commit({"type": "ROTATE_KEY", "issuerId": self.id,
                       "keyId": self.key_id, "pub": pub.hex(), "ts": ts})

    def issue(self, fields: dict, ts):
        names = sorted(fields)
        salts = {n: secrets.token_bytes(16) for n in names}
        leaves = [leaf(salts[n], n, fields[n]) for n in names]
        lv = merkle_levels(leaves)
        root = lv[-1][0]
        cred_id = "urn:cred:" + secrets.token_hex(8)
        msg = json.dumps({"id": cred_id, "root": root.hex(), "kid": self.key_id},
                         sort_keys=True).encode()
        sig = self.sk.sign(msg)
        self.L.commit({"type": "ISSUE", "credId": cred_id, "issuerId": self.id,
                       "root": root.hex(), "keyId": self.key_id, "ts": ts})
        # paket untuk holder (disimpan off-chain di wallet)
        return {"id": cred_id, "issuer": self.id, "kid": self.key_id,
                "root": root.hex(), "sig": sig.hex(), "names": names,
                "salts": {n: salts[n].hex() for n in names},
                "values": dict(fields), "_levels": lv}

    def set_status(self, kind, cred_id, ts, reason=None, new_id=None):
        tx = {"type": kind, "credId": cred_id, "issuerId": self.id, "ts": ts,
              "reason": reason}
        if new_id:
            tx["newCredId"] = new_id
        self.L.commit(tx)


# ---------------------------------------------------------------- Holder
def present(cred, disclose):
    """Selective disclosure: hanya field di 'disclose' + Merkle proof."""
    out = {"id": cred["id"], "issuer": cred["issuer"], "kid": cred["kid"],
           "root": cred["root"], "sig": cred["sig"], "fields": []}
    for n in disclose:
        i = cred["names"].index(n)
        out["fields"].append({"name": n, "value": cred["values"][n],
                              "salt": cred["salts"][n],
                              "proof": merkle_proof(cred["_levels"], i)})
    return out


# ---------------------------------------------------------------- Verifier
def verify(L: Ledger, pres, at_ts):
    """Hanya membaca ledger. Mengembalikan (ok, alasan)."""
    ok_chain, bad = L.validate_chain()
    if not ok_chain:
        return False, f"ledger rusak di blok {bad}"
    rec = L.state["creds"].get(pres["id"])
    if not rec:
        return False, "kredensial tidak terdaftar"
    if rec["root"] != pres["root"]:
        return False, "root tidak cocok dengan ledger"
    iss = L.state["issuers"].get(rec["issuerId"])
    if not iss or not iss["active"]:
        return False, "penerbit tidak aktif"
    key = iss["keys"].get(pres["kid"])
    if not key:
        return False, "kunci penerbit tidak dikenal"
    if not (key["from"] <= rec["issuedAt"] and (key["to"] is None or rec["issuedAt"] <= key["to"])):
        return False, "kunci tidak berlaku pada saat penerbitan"
    msg = json.dumps({"id": pres["id"], "root": pres["root"], "kid": pres["kid"]},
                     sort_keys=True).encode()
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key["pub"])).verify(
            bytes.fromhex(pres["sig"]), msg)
    except InvalidSignature:
        return False, "tanda tangan tidak valid"
    for f in pres["fields"]:
        lf = leaf(bytes.fromhex(f["salt"]), f["name"], f["value"])
        if not verify_proof(lf, f["proof"], bytes.fromhex(pres["root"])):
            return False, f"bukti Merkle field '{f['name']}' gagal"
    if rec["status"] != "ISSUED":
        return False, f"status kredensial: {rec['status']}"
    return True, "VALID"


# ---------------------------------------------------------------- Pengujian
def run():
    R = {"tests": [], "perf": {}, "chain": {}}

    def rec(tid, desc, expected, got, ok):
        R["tests"].append({"id": tid, "desc": desc, "expected": expected,
                           "got": got, "pass": bool(ok)})
        print(f"{tid:5} {'LULUS' if ok else 'GAGAL':5} {desc} -> {got}")

    L = Ledger(n_validators=4)
    univ = Issuer(L, "did:web:univ-contoh.ac.id", 1_790_000_100)

    # data simulasi (fiktif)
    fields = {"nama": "Siti Aminah (fiktif)", "nim": "207000001", "prodi": "S1 Informatika",
              "gelar": "S.Kom.", "ipk": "3.62", "tgl_lulus": "2026-08-23",
              "no_ijazah": "IJZ-2026-000123"}
    cred = univ.issue(fields, 1_790_000_200)

    # F-01 verifikasi penuh
    p = present(cred, ["nama", "prodi", "gelar", "tgl_lulus", "no_ijazah"])
    ok, why = verify(L, p, 1_790_000_300)
    rec("F-01", "Verifikasi ijazah valid (5 field diungkap)", "VALID", why, ok)

    # F-02 selective disclosure: hanya gelar+prodi, IPK/NIM tidak dikirim
    p2 = present(cred, ["gelar", "prodi"])
    sent = json.dumps(p2)
    leak = ("3.62" in sent) or ("207000001" in sent)
    ok, why = verify(L, p2, 1_790_000_300)
    rec("F-02", "Selective disclosure: hanya gelar+prodi; IPK & NIM tidak ada di paket",
        "VALID & tanpa bocor", f"{why}; bocor={leak}", ok and not leak)

    # F-03 pencabutan
    univ.set_status("REVOKE", cred["id"], 1_790_000_400, reason="ERR_DATA")
    ok, why = verify(L, p2, 1_790_000_500)
    rec("F-03", "Verifikasi setelah dicabut", "DITOLAK (REVOKED)", why,
        (not ok) and "REVOKED" in why)

    # F-04 re-issue + supersede (pemulihan kunci holder)
    cred2 = univ.issue(fields, 1_790_000_600)
    ok, why = verify(L, present(cred2, ["gelar"]), 1_790_000_700)
    rec("F-04", "Kredensial baru (re-issue ke DID baru) valid", "VALID", why, ok)

    # F-05 status transisi tidak sah (REVOKED -> REINSTATE)
    try:
        univ.set_status("REINSTATE", cred["id"], 1_790_000_800)
        rec("F-05", "Transisi terlarang REVOKED->ISSUED", "DITOLAK", "DITERIMA", False)
    except ValueError as e:
        rec("F-05", "Transisi terlarang REVOKED->ISSUED", "DITOLAK", str(e), True)

    # F-06 rotasi kunci: kredensial lama tetap valid
    univ.rotate(1_790_001_000, 2)
    ok, why = verify(L, present(cred2, ["gelar"]), 1_790_001_100)
    rec("F-06", "Kredensial lama tetap valid setelah rotasi kunci penerbit",
        "VALID", why, ok)

    # S-01 pemalsuan nilai field
    forged = present(cred2, ["gelar"])
    forged["fields"][0]["value"] = "S.T."
    ok, why = verify(L, forged, 1_790_001_200)
    rec("S-01", "Pemalsuan nilai field (gelar diubah)", "DITOLAK", why, not ok)

    # S-02 tanda tangan palsu / penerbit tidak terdaftar
    rogue_sk, _ = new_key()
    forged2 = present(cred2, ["gelar"])
    msg = json.dumps({"id": forged2["id"], "root": forged2["root"], "kid": forged2["kid"]},
                     sort_keys=True).encode()
    forged2["sig"] = rogue_sk.sign(msg).hex()
    ok, why = verify(L, forged2, 1_790_001_200)
    rec("S-02", "Tanda tangan oleh kunci penyerang", "DITOLAK", why, not ok)

    # S-03 penerbit tak terdaftar mencoba menerbitkan
    try:
        L.commit({"type": "ISSUE", "credId": "urn:cred:evil", "issuerId": "did:web:palsu.id",
                  "root": "00" * 32, "keyId": "x", "ts": 1_790_001_300})
        rec("S-03", "Penerbit tak terdaftar menerbitkan", "DITOLAK", "DITERIMA", False)
    except PermissionError as e:
        rec("S-03", "Penerbit tak terdaftar menerbitkan", "DITOLAK", str(e), True)

    # S-04 penerbit lain mencabut kredensial bukan miliknya
    other = Issuer(L, "did:web:lsp-contoh.or.id", 1_790_001_400)
    try:
        other.set_status("REVOKE", cred2["id"], 1_790_001_500)
        rec("S-04", "Penerbit lain mencabut kredensial bukan miliknya", "DITOLAK", "DITERIMA", False)
    except PermissionError as e:
        rec("S-04", "Penerbit lain mencabut kredensial bukan miliknya", "DITOLAK", str(e), True)

    # S-05 tamper ledger (ubah root di blok lama)
    idx = next(i for i, b in enumerate(L.blocks) if b["txs"][0].get("credId") == cred2["id"])
    saved = L.blocks[idx]["txs"][0]["root"]
    L.blocks[idx]["txs"][0]["root"] = "ab" * 32
    ok_chain, bad = L.validate_chain()
    rec("S-05", "Perubahan data di blok lama terdeteksi validasi rantai",
        "TERDETEKSI", f"rantai rusak di blok {bad}", not ok_chain and bad == idx)
    L.blocks[idx]["txs"][0]["root"] = saved
    R["chain"]["tamper_detected_at_block"] = bad

    # S-06 brute-force tebak nilai field tanpa salt vs dengan salt
    guess_space = [f"{x:09d}" for x in range(207000000, 207001000)]
    unsalted = hb(b"\x00" + b"nim=207000001")  # skema naif: hash tanpa salt
    found_naive = any(hb(b"\x00" + f"nim={g}".encode()) == unsalted for g in guess_space)
    lf_target = leaf(bytes.fromhex(cred2["salts"]["nim"]), "nim", "207000001")
    found_salted = any(leaf(b"\x00" * 16, "nim", g) == lf_target for g in guess_space)
    rec("S-06", "Tebak NIM dari hash: tanpa salt vs ber-salt (1000 kandidat)",
        "tanpa salt bocor; ber-salt aman", f"tanpa salt ditemukan={found_naive}; ber-salt ditemukan={found_salted}",
        found_naive and not found_salted)

    # S-07 kuorum tidak tercapai
    try:
        L.commit({"type": "DEACTIVATE_ISSUER", "issuerId": other.id, "ts": 1_790_001_600}, votes=2)
        rec("S-07", "Commit dengan 2 dari 4 suara (n=4, f=1, butuh 3)", "DITOLAK", "DITERIMA", False)
    except PermissionError as e:
        rec("S-07", "Commit dengan 2 dari 4 suara (n=4, f=1, butuh 3)", "DITOLAK", str(e), True)

    # S-08 penerbit dinonaktifkan -> kredensialnya tidak lagi terverifikasi
    L.commit({"type": "DEACTIVATE_ISSUER", "issuerId": univ.id, "ts": 1_790_001_700})
    ok, why = verify(L, present(cred2, ["gelar"]), 1_790_001_800)
    rec("S-08", "Penerbit dinonaktifkan melalui governance", "DITOLAK", why, not ok)

    # P-01 performa (sandbox, bukan benchmark jaringan)
    L2 = Ledger(4)
    u2 = Issuer(L2, "did:web:bench.ac.id", 1)
    N = 300
    t0 = time.perf_counter()
    creds = [u2.issue(fields, 10 + i) for i in range(N)]
    t_issue = (time.perf_counter() - t0) / N * 1000
    pres = [present(c, ["gelar", "prodi"]) for c in creds]
    t0 = time.perf_counter()
    oks = 0
    # verifikasi tanpa re-validasi rantai penuh per kredensial: pakai satu validasi + cek per item
    chain_ok, _ = L2.validate_chain()
    t_chain = time.perf_counter() - t0
    t0 = time.perf_counter()
    for pr in pres:
        rec_ = L2.state["creds"][pr["id"]]
        iss = L2.state["issuers"][rec_["issuerId"]]
        key = iss["keys"][pr["kid"]]
        msg = json.dumps({"id": pr["id"], "root": pr["root"], "kid": pr["kid"]}, sort_keys=True).encode()
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key["pub"])).verify(bytes.fromhex(pr["sig"]), msg)
        good = rec_["root"] == pr["root"] and rec_["status"] == "ISSUED"
        for f in pr["fields"]:
            good &= verify_proof(leaf(bytes.fromhex(f["salt"]), f["name"], f["value"]),
                                 f["proof"], bytes.fromhex(pr["root"]))
        oks += good
    t_ver = (time.perf_counter() - t0) / N * 1000
    R["perf"] = {"N": N, "issue_ms_per_cred": round(t_issue, 3),
                 "verify_ms_per_cred": round(t_ver, 3),
                 "verify_throughput_per_s": round(1000 / t_ver, 1),
                 "chain_validation_s_for_%d_blocks" % len(L2.blocks): round(t_chain, 4),
                 "all_valid": oks == N and chain_ok}
    rec("P-01", f"Performa verifikasi {N} kredensial (sandbox)", ">= 25 verifikasi/detik",
        f"{R['perf']['verify_throughput_per_s']} /detik; terbitkan {R['perf']['issue_ms_per_cred']} ms/kred",
        R["perf"]["verify_throughput_per_s"] >= 25 and oks == N)

    # --- tabel mini-blockchain untuk laporan (3 blok pertama + root contoh)
    L3 = Ledger(4)
    u3 = Issuer(L3, "did:web:univ-contoh.ac.id", 1_790_000_100)
    c3 = u3.issue(fields, 1_790_000_200)
    R["chain"]["blocks"] = [{"height": b["height"], "type": b["txs"][0]["type"],
                             "prev": b["prev"], "hash": b["hash"]} for b in L3.blocks]
    R["chain"]["example_root"] = c3["root"]
    R["chain"]["example_leaves"] = [
        {"field": n, "leaf": leaf(bytes.fromhex(c3["salts"][n]), n, c3["values"][n]).hex()}
        for n in c3["names"]]
    R["chain"]["n_blocks_main"] = len(L.blocks)
    # uji hash: ubah 1 karakter input -> avalanche
    a = hashlib.sha256(b"gelar=S.Kom.").hexdigest()
    b_ = hashlib.sha256(b"gelar=S.Kom,").hexdigest()
    diff = sum(x != y for x, y in zip(bin(int(a, 16))[2:].zfill(256), bin(int(b_, 16))[2:].zfill(256)))
    R["chain"]["avalanche"] = {"a": a, "b": b_, "bits_diff": diff}

    npass = sum(t["pass"] for t in R["tests"])
    R["summary"] = {"total": len(R["tests"]), "pass": npass}
    print(f"\nRingkasan: {npass}/{len(R['tests'])} lulus")
    with open(os.path.join(os.path.dirname(__file__), "results.json"), "w") as fh:
        json.dump(R, fh, indent=1)
    return R


if __name__ == "__main__":
    run()
