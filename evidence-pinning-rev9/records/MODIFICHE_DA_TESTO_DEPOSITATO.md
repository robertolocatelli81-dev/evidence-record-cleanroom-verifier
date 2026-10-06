# Passo 0 — checker aggiornato al testo DEPOSITATO della -03 (prima di toccare i vettori)

Scritto 2026-10-06 tra 17:40Z e 17:50Z, PRIMA di eseguire qualunque vettore della rev 9.

## Oggetti
- Checker di partenza: `gtm/x402_tsc4_dash03/es_check.py`, sha256 `0c430ecae770ae5dfce7e1b5a8bc159dc941a4e22777e6b5f707efcf5c856f5f`
  (costruito a freddo il 26/09 da `spec/draft-03@5a718639288a.txt`, sha256 `ad009473…a451b`, poi allineato il 26/09
  alla decisione NUL di TKCollective e il 29/09 alla regola resource_sha256 di -03@057abd7 — allineamenti già
  dichiarati nel codice come NON indipendenti).
- Testo depositato: `draft-krausz-verification-state-03.txt`, sha256 `1d142b3effbfc612dca388567902f63823b45dcf69eece423e6b2b9a28dcbed9`.
  Provenienza MISURATA oggi 17:38Z: scaricato da `https://www.ietf.org/archive/id/draft-krausz-verification-state-03.txt`,
  stesso sha256 (= valore nel README rev 9).
- Diff a frasi: `DIFF_03_cold_vs_filed_5.3-5.4.txt` (sha256 `f93a6d3d…4e74e`, 73 righe). Ho riletto per intero §5.3–§5.4.2
  del depositato (righe 714–1547), non solo il diff.
- Copia aggiornata: `runner/es_check_filed.py`.

## Frase per frase (diff → codice)

| # | Frase del depositato | Effetto sul codice |
|---|---|---|
| M1 | §5.3.2 (righe 868–875): «snippet_sha256_present_when_unpinned is a presence check: it takes the member's presence as input, not its form, so it is evaluated whatever form the value takes, and an unpinned entry whose non-null value is also not 64 lowercase hexadecimal characters reports it alongside snippet_sha256_not_lowercase_hex64. It still takes pinned as input, so a malformed pinned value suppresses it…»; §5.4.1(a) (righe 1266–1272): «Every condition named \*_present_when_\* or \*_absent_when_\* takes the tested member's presence as its input, not its form… a malformed status member it depends on, such as pinned, still suppresses it.» | **Nessun cambio.** Il codice valutava già così (CHOICE 1 del 26/09 + seconda tornata dopo la decisione del 26/09). Verificato per ogni condizione del registro con quei nomi: `snippet_sha256_absent_when_pinned`, `snippet_sha256_present_when_unpinned`, `content_kind_present_when_unpinned` sono valutate sotto `pinned_ok` e non soppresse dalla forma del membro testato. CHOICE 1 ora è testo. |
| M2 | §5.3.2 (righe 917–930): «resource_sha256 (string or absent/null, OPTIONAL) … Absent and null are equivalent (as for content_kind) … neither is malformed … A non-null value MUST be exactly 64 lowercase hexadecimal characters … MUST be absent or null when content_kind is full_resource» | **Nessun cambio.** Già nel codice dal 29/09 (frasi identiche a -03@057abd7). CHOICE 3/3b ora sono testo. |
| M3 | §5.3.2 (righe 988–991): «member_contains_nul is a content rule, not a type or form check: it is reported alongside whatever other conditions the same member's rules report, and it suppresses nothing under paragraph (a) of Section 5.4.1.» | **Nessun cambio.** Già nel codice dal 26/09 (dopo la decisione su tsc#4). CHOICE 9 per il NUL ora è testo. |
| M4 | §5.4 (righe 1146–1152): «Except where a step states otherwise (a content-hash mismatch in the evidence-set step, Section 5.4.1, resolves unknown and does not halt), any check that runs and fails makes the receipt malformed…» | **Nessun cambio.** Coerente con (d)/(i) già implementati (content_differs → unknown, non halt). |
| M5 | §5.4.1(d) (invariato): «If the verifier holds candidate content for a pinned item, compute its SHA-256 and compare with snippet_sha256.» | **Cambio NON semantico**: `resolve(payload, held=None, held_sha256=None)`. `held_sha256` = digest che il verificatore ha già calcolato sui byte che detiene; stesso confronto. Serve all'harness: alcuni vettori danno il digest ricalcolato, non i byte. Un elemento non pinned resta `content_not_held` anche se compare in `held_sha256`. |
| M6 | §5.4 passo 1 e §5.4.2 (righe 1181–1189, 1470–1547): key_unresolved / policy refusal / signature_invalid, input di completezza. | **Fuori perimetro**: il checker implementa solo il passo dell'evidence-set (§5.4.1). Il README rev 9 dichiara che il corpus non copre §5.4.2. Nessun cambio. |

## Scelta rimasta aperta, emersa rileggendo il depositato (non decisa dal testo, NON cambiata)
- **CHOICE 3c.** Con `content_kind: full_resource` e un `resource_sha256` non nullo e NON esadecimale, il codice riporta
  `resource_sha256_present_for_full_resource` accanto a `resource_sha256_not_lowercase_hex64`. La regola generale di
  §5.4.1(a) sopprime una condizione se un membro che prende in input ha fallito il proprio controllo di forma;
  l'eccezione di presenza nomina solo `*_present_when_*` / `*_absent_when_*`, mentre questa è `*_present_for_*`.
  Lettura testuale stretta → andrebbe soppressa; lettura «è anch'essa un controllo di presenza» → riportata. Lasciata
  com'era (B: il testo non decide). Nessun vettore rev 9 ha un resource_sha256 non esadecimale (letto dagli INPUT).

## Selftest del 26/09 rieseguito (cosa cambia e perché)
Comando (per ciascun interprete, in cartella di prova con `es_check.py` = la copia, più `selftest.py`, `run_vectors.py`,
`es_check.py.pre_R1_20260929.bak` originali):
`<python> -B selftest.py`
- Originale e copia, Python 3.9.25 / 3.11.2 / 3.13.15: **31/31** controlli, controllo R1 del banco OK (regola vecchia →
  malformed), controllo negativo «senza soppressione» sul caso 1 → insieme diverso. Le 6 uscite sono byte-identiche
  (sha256 `690673dbdb364a7a…`). **Non cambia nulla**, perché nessuna regola semantica è cambiata (M1–M4 erano già nel codice;
  M5 aggiunge un ramo che il selftest vecchio non usa).
- Nuovo `selftest_filed.py` per il solo ramo M5: **5/5** su tutti e tre gli interpreti; controllo positivo (confronto
  invertito) passa **0/5** → il test sa fallire.

## Cosa questo NON dice
- Che il checker sia indipendente dal testo di -03@057abd7 o dalle decisioni del thread: non lo è per R1 e NUL
  (dichiarato nel codice dal 26–29/09). È indipendente dal codice di babyblueviper1 e dalle attese della rev 9.
