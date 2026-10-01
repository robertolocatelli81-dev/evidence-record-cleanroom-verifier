"""secp256k1: recupero della chiave pubblica da firma ECDSA, in Python puro (stdlib).

Serve a una cosa sola: verificare la firma dell'esempio nella spec x402 exact-EVM senza installare
un ecosistema. Nessuna dipendenza (ecdsa/coincurve/eth-keys sono tutte assenti nell'ambiente).
NON e' codice di produzione: niente protezioni side-channel, non firma nulla di reale.
"""
from __future__ import annotations

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _inv(a, m):
    return pow(a, m - 2, m)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def _mul(k, p):
    r = None
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def recover_public_key(msg_hash: bytes, r: int, s: int, rec_id: int):
    """Q = r^-1 (sR - eG). rec_id ∈ {0,1} (dal parametro v della firma Ethereum: v-27)."""
    if not (1 <= r < N and 1 <= s < N):
        raise ValueError("r/s fuori range")
    if rec_id not in (0, 1, 2, 3):
        # Bug trovato dalla cross-validazione contro libsecp256k1 (11/09/2026): con v=0 il chiamante
        # calcola rec_id = 0-27 = -27, e senza questo controllo lo shift `-27 >> 1` produceva un punto
        # qualsiasi e un indirizzo INVENTATO, mentre libsecp256k1 rifiuta. Un recupero che non rifiuta
        # un recovery id impossibile fabbrica firmatari.
        raise ValueError(f"recovery id {rec_id} fuori da {{0,1,2,3}}")
    x = r + N * (rec_id >> 1)
    if x >= P:
        raise ValueError("x fuori campo")
    alpha = (pow(x, 3, P) + 7) % P
    beta = pow(alpha, (P + 1) // 4, P)          # p ≡ 3 (mod 4): radice quadrata diretta
    if pow(beta, 2, P) != alpha:
        raise ValueError("punto non sulla curva")
    y = beta if (beta % 2) == (rec_id & 1) else P - beta
    R = (x, y)
    e = int.from_bytes(msg_hash, "big") % N
    Q = _mul(_inv(r, N), _add(_mul(s, R), _mul(N - e, (GX, GY))))
    if Q is None:
        # Punto all'infinito: succede quando sR == eG (costruibile a tavolino: R = kG, s = e/k).
        # Non e' una chiave pubblica. libsecp256k1 fallisce il recupero; un'implementazione che
        # lo serializza (address(0) alla ecrecover, o keccak di 64 byte zero) fabbrica un firmatario.
        raise ValueError("recupero al punto all'infinito: nessuna chiave pubblica")
    return Q


def public_key_to_address(pub, keccak) -> str:
    x, y = pub
    return "0x" + keccak(x.to_bytes(32, "big") + y.to_bytes(32, "big")).hex()[-40:]


def sign(msg_hash: bytes, priv: int, k: int):
    """Firma ECDSA — usata SOLO per il controllo positivo (k fornito, non e' produzione)."""
    R = _mul(k, (GX, GY))
    r = R[0] % N
    e = int.from_bytes(msg_hash, "big") % N
    s = (_inv(k, N) * (e + r * priv)) % N
    rec = (R[1] & 1) ^ (1 if s > N // 2 else 0)
    if s > N // 2:
        s = N - s
    return r, s, rec


def self_test(keccak):
    """Controllo positivo NON circolare: firmo con una chiave nota, recupero, confronto l'indirizzo."""
    priv = 0x4646464646464646464646464646464646464646464646464646464646464646
    pub_atteso = _mul(priv, (GX, GY))
    addr_atteso = public_key_to_address(pub_atteso, keccak)
    h = keccak(b"controllo positivo x402")
    r, s, rec = sign(h, priv, k=0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF)
    pub_rec = recover_public_key(h, r, s, rec)
    return {"indirizzo_atteso": addr_atteso,
            "indirizzo_recuperato": public_key_to_address(pub_rec, keccak),
            "ok": pub_rec == pub_atteso}
