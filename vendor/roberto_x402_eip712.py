"""Keccak-256 + EIP-712 in Python puro (stdlib), per generare e verificare i vettori `offerDigest`.

Nessuna dipendenza esterna: l'ambiente non ha pycryptodome/pysha3/eth-hash, e un vettore di
conformità non deve richiedere un ecosistema per essere controllato. Keccak-256 NON è SHA3-256:
differiscono per il byte di padding (0x01 contro 0x06), quindi hashlib.sha3_256 non è sostituibile.
La correttezza è verificata contro vettori pubblici noti in `self_test()`.
"""
from __future__ import annotations

import re

_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
       0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
       0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
       0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_MASK = (1 << 64) - 1


def _rotl(x, n):
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f(A):
    for rnd in range(24):
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rotl(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rotl(A[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & _MASK & B[(x + 2) % 5][y])
        A[0][0] ^= _RC[rnd]
    return A


def keccak256(data: bytes) -> bytes:
    """Keccak-256 originale (padding 0x01), quello usato da Ethereum — non SHA3-256 (0x06)."""
    rate = 136
    A = [[0] * 5 for _ in range(5)]
    m = bytearray(data)
    m.append(0x01)                                   # padding Keccak, NON 0x06
    while len(m) % rate != 0:
        m.append(0x00)
    m[-1] |= 0x80
    for off in range(0, len(m), rate):
        blocco = m[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            A[x][y] ^= int.from_bytes(blocco[i * 8:(i + 1) * 8], "little")
        A = _keccak_f(A)
    out = b""
    while len(out) < 32:
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            out += A[x][y].to_bytes(8, "little")
            if len(out) >= 32:
                break
        if len(out) < 32:
            A = _keccak_f(A)
    return bytes(out[:32])


# ----------------------------------------------------------------------------- EIP-712
def encode_type(primary: str, types: dict) -> bytes:
    """encodeType: `Primary(tipo nome,...)` seguito dai tipi referenziati in ordine alfabetico."""
    def deps(nome, visti):
        if nome in visti or nome not in types:
            return visti
        visti = visti | {nome}
        for campo in types[nome]:
            base = campo["type"].split("[")[0]
            if base in types:
                visti = deps(base, visti)
        return visti
    ordinati = [primary] + sorted(deps(primary, set()) - {primary})
    fuori = "".join(f"{t}({','.join(f'{c[chr(116)+chr(121)+chr(112)+chr(101)]} {c[chr(110)+chr(97)+chr(109)+chr(101)]}' for c in types[t])})" for t in ordinati)
    return fuori.encode()


def type_hash(primary: str, types: dict) -> bytes:
    return keccak256(encode_type(primary, types))


class ValoreNonConforme(ValueError):
    """Il valore JSON non ha la forma STRETTA che questa libreria ammette per il suo tipo EIP-712."""


# Codifica STRETTA dei valori JSON (regola adottata il 25/09/2026, dopo il fuzz di input malformati).
#
# Prima ogni valore passava per int() / str() / bytes.fromhex(), che NORMALIZZANO: 10000.9 diventava
# 10000, "١٠٠٠٠" (cifre arabo-indiche), " 10000\n", "10_000" e "+10000" diventavano 10000, "XX"+hex
# passava per un indirizzo, bytes.fromhex saltava gli spazi, il bool "false" valeva true, la stringa
# "123" dichiarata uint256[] diventava l'array [1, 2, 3]. Risultato misurato: `accept` su messaggi il
# cui JSON MOSTRATO non e' il messaggio FIRMATO — un differenziale di parsing fra chi legge e chi
# verifica. Qui un valore ha UNA forma testuale ammessa per tipo; tutto il resto solleva
# ValoreNonConforme, che per il runner e' `encoding_error`.
#
#   uintN / intN   N in {8, 16, …, 256}. Intero JSON (non bool, non float: 10000.0 e' un float), oppure
#                  stringa decimale ASCII canonica: ^(0|[1-9][0-9]*)$ per uintN, ^-?(0|[1-9][0-9]*)$ per
#                  intN, "-0" escluso; niente segno "+", spazi, underscore, zeri iniziali, "0x".
#                  Poi controllo di range del tipo.
#   address        stringa ^0x[0-9a-fA-F]{40}$ esatta (il checksum EIP-55 NON e' verificato: vettore 040).
#   bytes32        stringa ^0x[0-9a-fA-F]{64}$ esatta. (Gli altri bytesN restano fuori profilo.)
#   bytes          stringa ^0x([0-9a-fA-F]{2})*$.
#   string         str JSON (un intero NON diventa la sua forma decimale).
#   bool           true / false JSON.
#   T[] / T[k]     array JSON; per T[k] esattamente k elementi.
#
# Le classi di caratteri sono esplicite ([0-9], non \d, che in Python accetta cifre Unicode) e il
# confronto usa fullmatch (un `$` accetta un "\n" finale).
_RE_DEC_UINT = re.compile(r"0|[1-9][0-9]{0,77}")       # 2**256 ha 78 cifre: nessuna int() quadratica
_RE_DEC_INT = re.compile(r"-?(?:0|[1-9][0-9]{0,77})")
_RE_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_RE_BYTES32 = re.compile(r"0x[0-9a-fA-F]{64}")
_RE_BYTES = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
_RE_TIPO_INT = re.compile(r"(u?)int([0-9]+)")
_RE_ARRAY = re.compile(r"(.+)\[((?:[1-9][0-9]*)?)\]")


def _intero_stretto(tipo: str, firmato: bool, valore) -> int:
    if isinstance(valore, bool):                     # bool e' sottoclasse di int in Python
        raise ValoreNonConforme(f"{tipo}: bool non e' un intero")
    if isinstance(valore, int):
        return valore
    if isinstance(valore, str):
        if (_RE_DEC_INT if firmato else _RE_DEC_UINT).fullmatch(valore) and valore != "-0":
            return int(valore)
        raise ValoreNonConforme(f"{tipo}: stringa non in forma decimale canonica: {valore[:40]!r}")
    raise ValoreNonConforme(f"{tipo}: atteso intero JSON o stringa decimale, trovato {type(valore).__name__}")


def _stringa_che_combacia(tipo: str, regex, valore) -> str:
    if not isinstance(valore, str) or not regex.fullmatch(valore):
        raise ValoreNonConforme(f"{tipo}: valore non conforme a {regex.pattern}: {str(valore)[:48]!r}")
    return valore


def encode_value(tipo: str, valore, types: dict | None = None) -> bytes:
    """encodeData secondo EIP-712, con codifica STRETTA dei valori JSON (vedi la regola sopra).

    Copre i tipi atomici del profilo x402 (string, uintN/intN, address, bool, bytes32, bytes), le
    struct annidate (hashStruct ricorsivo) e gli ARRAY: l'encoding di un array e' keccak256 della
    CONCATENAZIONE degli encodeData dei suoi elementi — non del JSON dell'array. Il supporto agli
    array e' stato aggiunto quando il vettore 019 lo ha preteso: prima la libreria sollevava
    ValueError, che e' esattamente il buco che quel vettore esiste per trovare.

    Un valore che non ha la forma ammessa per il suo tipo solleva ValoreNonConforme: la libreria non
    indovina cosa intendeva il mittente (vettori 056-075).
    """
    m = _RE_ARRAY.fullmatch(tipo)
    if m:
        base, lunghezza = m.group(1), m.group(2)
        if not isinstance(valore, list):
            raise ValoreNonConforme(f"{tipo}: atteso un array JSON, trovato {type(valore).__name__}")
        if lunghezza and len(valore) != int(lunghezza):
            raise ValoreNonConforme(f"{tipo}: {len(valore)} elementi, il tipo ne dichiara {lunghezza}")
        return keccak256(b"".join(encode_value(base, el, types) for el in valore))
    if types and tipo in types:
        return hash_struct(tipo, types, valore)
    if tipo == "string":
        if not isinstance(valore, str):
            raise ValoreNonConforme(f"string: trovato {type(valore).__name__}")
        return keccak256(valore.encode("utf-8"))
    if tipo == "bytes":
        # Dal JSON arriva una stringa "0x…", non byte raw (bug dormiente trovato dalla revisione
        # Gemini 3.1 Pro dell'11/09/2026, vettore 054). bytes.fromhex salta gli spazi: la regex prima.
        return keccak256(bytes.fromhex(_stringa_che_combacia(tipo, _RE_BYTES, valore)[2:]))
    m = _RE_TIPO_INT.fullmatch(tipo)
    if m:
        # `intN` e' con segno: complemento a due su 32 byte (EIP-712: "encoded as uint256/int256").
        # Prima mancava signed=… e un int256 negativo — messaggio VALIDO — sollevava OverflowError:
        # una libreria che rifiuta un messaggio valido e' peggio di una che esplode. Vettore 053.
        # Un valore fuori dal range del tipo solleva OverflowError -> per il runner e' encoding_error.
        firmato, bits = m.group(1) == "", int(m.group(2))
        if bits % 8 or not 8 <= bits <= 256 or m.group(2).startswith("0"):
            raise ValoreNonConforme(f"{tipo}: larghezza non ammessa da EIP-712 (8..256, multipla di 8)")
        v = _intero_stretto(tipo, firmato, valore)
        if not firmato and not (0 <= v < 2 ** bits):
            raise OverflowError(f"{tipo}: {v} fuori range")
        if firmato and not (-(2 ** (bits - 1)) <= v < 2 ** (bits - 1)):
            raise OverflowError(f"{tipo}: {v} fuori range")
        return v.to_bytes(32, "big", signed=firmato)
    if tipo == "address":
        return bytes(12) + bytes.fromhex(_stringa_che_combacia(tipo, _RE_ADDRESS, valore)[2:])
    if tipo == "bool":
        if not isinstance(valore, bool):
            raise ValoreNonConforme(f"bool: atteso true/false JSON, trovato {type(valore).__name__}")
        return (1 if valore else 0).to_bytes(32, "big")
    if tipo == "bytes32":
        return bytes.fromhex(_stringa_che_combacia(tipo, _RE_BYTES32, valore)[2:])
    raise ValueError(f"tipo non gestito nel profilo x402: {tipo}")


_ORDINE_DOMINIO_EIP712 = [("name", "string"), ("version", "string"), ("chainId", "uint256"),
                          ("verifyingContract", "address"), ("salt", "bytes32")]
_RE_NOME_STRUCT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*", re.ASCII)
_RE_TIPO_ATOMICO = re.compile(r"u?int[0-9]*|address|bool|string|bytes[0-9]*", re.ASCII)


def valida_struttura(dominio, types) -> None:
    """Il dominio e i nomi dei tipi hanno UNA sola lettura (25/09/2026, revisione 4 menti round 2).

    Prima venivano ignorati: membri del dominio fuori dall'elenco EIP-712 (`chainID`, `verifyingcontract`),
    un `types.EIP712Domain` dichiarato ma diverso dai campi presenti (anche `chainId` dichiarato `string`),
    e una struct chiamata come un tipo atomico (`address`), che ne oscurava il tipo. In tutti e tre i casi il
    JSON mostrato non era il messaggio firmato; eth-account li rifiuta o calcola un digest diverso.
    """
    if not isinstance(dominio, dict) or not isinstance(types, dict):
        raise ValoreNonConforme("domain e types devono essere oggetti JSON")
    noti = [n for n, _ in _ORDINE_DOMINIO_EIP712]
    estranei = sorted(k for k in dominio if k not in noti)
    if estranei:
        raise ValoreNonConforme(f"domain: membri estranei a EIP-712 {estranei} (i nomi ammessi sono {noti})")
    if "EIP712Domain" in types:
        atteso = [{"name": n, "type": t} for n, t in _ORDINE_DOMINIO_EIP712 if n in dominio]
        if types["EIP712Domain"] != atteso:
            raise ValoreNonConforme("types.EIP712Domain non coincide con i campi del domain (nomi, tipi e ordine EIP-712)")
    for nome in types:
        if not isinstance(nome, str) or not _RE_NOME_STRUCT.fullmatch(nome):
            raise ValoreNonConforme(f"nome di struct non valido: {nome!r}")
        if nome != "EIP712Domain" and _RE_TIPO_ATOMICO.fullmatch(nome):
            raise ValoreNonConforme(f"struct chiamata come un tipo atomico: {nome!r} ne oscurerebbe il tipo")


def hash_struct(primary: str, types: dict, dati: dict) -> bytes:
    parti = [type_hash(primary, types)]
    for campo in types[primary]:
        if campo["name"] not in dati:
            raise KeyError(f"campo mancante nella struct {primary}: {campo['name']} "
                           f"(EIP-712 ha una member list FISSA: un campo assente non e' omissione, e' errore)")
        parti.append(encode_value(campo["type"], dati[campo["name"]], types))
    return keccak256(b"".join(parti))


# profilo x402: il dominio ha 3 campi (name, version, chainId) — vedi §3.2 della extension
_DOMINIO_X402 = [{"name": "name", "type": "string"},
                 {"name": "version", "type": "string"},
                 {"name": "chainId", "type": "uint256"}]


def domain_separator(dominio: dict, campi: list | None = None) -> bytes:
    """domainSeparator. `campi` permette il dominio a 4 membri della EIP-712 canonica (con
    verifyingContract), usato SOLO per il controllo positivo esterno contro i digest pubblicati
    nella EIP stessa: un banco che non riproduce quelli non ha titolo per emettere vettori."""
    return hash_struct("EIP712Domain", {"EIP712Domain": campi or _DOMINIO_X402}, dominio)


def signing_digest(dominio: dict, primary: str, types: dict, messaggio: dict,
                   campi_dominio: list | None = None) -> bytes:
    """Il digest EIP-712 firmato: keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct(message))."""
    valida_struttura(dominio, types)
    return keccak256(b"\x19\x01" + domain_separator(dominio, campi_dominio)
                     + hash_struct(primary, types, messaggio))


def self_test() -> dict:
    """Il banco deve dimostrare di funzionare PRIMA di produrre vettori: Keccak contro valori pubblici."""
    noti = {
        b"": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        b"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        b"testing": "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02",
    }
    ok_keccak = all(keccak256(k).hex() == v for k, v in noti.items())
    import hashlib
    diverso_da_sha3 = keccak256(b"abc").hex() != hashlib.sha3_256(b"abc").hexdigest()
    # encodeType su un caso di riferimento EIP-712 (esempio canonico della EIP)
    tipi_ref = {"Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
                "Mail": [{"name": "from", "type": "Person"}, {"name": "to", "type": "Person"},
                         {"name": "contents", "type": "string"}]}
    et = encode_type("Mail", tipi_ref).decode()
    ok_encode = et == "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
    # CONTROLLO POSITIVO ESTERNO: i digest dell'esempio "Mail" sono pubblicati NELLA EIP-712.
    # Riprodurli e' la prova che questo banco calcola EIP-712 e non qualcosa che gli somiglia.
    campi_dom = [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                 {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}]
    dom = {"name": "Ether Mail", "version": "1", "chainId": 1,
           "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"}
    msg = {"from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
           "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
           "contents": "Hello, Bob!"}
    ds = domain_separator(dom, campi_dom).hex()
    hs = hash_struct("Mail", tipi_ref, msg).hex()
    sd = signing_digest(dom, "Mail", tipi_ref, msg, campi_dom).hex()
    atteso_ds = "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
    atteso_hs = "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
    atteso_sd = "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
    ok_eip = (ds == atteso_ds and hs == atteso_hs and sd == atteso_sd)
    return {"keccak_vettori_pubblici": ok_keccak, "keccak_diverso_da_sha3_256": diverso_da_sha3,
            "encode_type_riferimento_EIP712": ok_encode,
            "eip712_esempio_canonico_riprodotto": ok_eip,
            "domainSeparator": ds, "hashStruct": hs, "signingDigest": sd,
            "ok": ok_keccak and diverso_da_sha3 and ok_encode and ok_eip}


if __name__ == "__main__":
    import json
    print(json.dumps(self_test(), indent=2))
