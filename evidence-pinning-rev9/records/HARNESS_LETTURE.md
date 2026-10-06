# Harness H1–H4 — letture NOSTRE (scritte PRIMA di eseguire qualunque vettore)

Scritto 2026-10-06 ~17:52Z. Fonte unica: README rev 9 a `4de7782` (copia `README_rev9_4de7782.md`, sha256
`4a8ddbdb643a58c938bcbe5894e151e88677a5694ae40b6f4b3efab95bbdaec9`), sezioni «H1–H5 comparability» e «Runner notes
(non-normative)», più la FORMA degli input del corpus (`rev9.json`, sha256 `3c5f4bf4…73724`).

## Cosa ho visto prima di eseguire (dichiarazione)
- Le Runner notes contengono la tabella dei 3 vettori a doppia condizione (nomi dei vettori, condizione nominata,
  seconda condizione nel run di babyblueviper1). L'ho letta perché è dentro la fonte che la PREREG mi assegna per
  l'harness. Quindi il confronto con quella tabella NON è cieco. Nessuna lettura qui sotto è stata scelta per far
  tornare quella tabella; dove una lettura la tocca lo dico.
- Del corpus ho letto: gli `id`, i `designation` (solo le categorie), gli `input` per intero, i `note`, i NOMI delle
  chiavi di `computed`; delle `expect` solo il tipo (47 stringhe), non il contenuto. NON letti: `expect`, `condition`,
  i valori di `computed`, `contributed_checker_result`, `header` oltre al censimento troncato a 600 caratteri (che
  elenca i nomi delle condizioni nominate — visto, dichiarato).
- Metodo aggiunto alla PREREG (più stretto, non più largo): gli output GREZZI del checker sui 47 vettori vengono
  congelati con hash (`OUTPUT_grezzi.json`) PRIMA di scrivere il runner di confronto, cioè prima di leggere qualunque
  `expect`/`condition`.

## Letture decise dal testo delle note (nessuna scelta)
- **H1**: dove un `evidence_set` (dato o costruito da H2) non ha `evidence_set_version`, aggiungo `"ao-evidence-set-v1"`.
- **H4**: `set_retrieved_at` → membro `retrieved_at` dell'`evidence_set`.
- **H3, seconda e terza riga**: se il vettore porta `evidence_root` (valore o null esplicito) lo tengo com'è; se non è
  calcolabile resta assente.
- **H5**: nessuna rinomina (le note: «under rev 9 the map has nothing left to rename»). Il checker usa i nomi -03.

## LETTURE NOSTRE (le note non bastano)
- **L1 — H2, cosa contiene l'involucro.** Le note dicono «wrap a bare `entry` / `sources` fragment». Lettura: `entry` →
  `{"evidence_set": {"sources": [entry]}}`; `sources` → `{"evidence_set": {"sources": sources}}`. NON aggiungo
  `source_count`, `pinned_count`, `fully_pinned`: si applica il fallback di §5.3.1 («When source_count, pinned_count,
  and fully_pinned are all absent, resolution derives all three the same way and MUST NOT halt»).
- **L2 — H3, «is not about the root».** Le note non dicono come lo si decide. Lettura: NON uso `condition` né
  `designation`; applico H3 a ogni vettore che omette il membro, e decide solo la calcolabilità (L3). Misura di
  robustezza, eseguita insieme al run: la lettura alternativa «sono sulla radice i vettori il cui `id` contiene
  `root`» deve produrre input identici byte per byte (nel corpus l'unico vettore con `root` nell'id che omette il
  membro è `evi-empty-root-null`, dove nessuna voce è pinned e la radice non è calcolabile). Se gli input differissero,
  lo riporto. La lettura «dalla `condition`» si può confrontare solo DOPO il congelamento.
- **L3 — H3, «where the root cannot be computed from the fragment».** Lettura: la radice è calcolabile se e solo se
  `sources` è una lista di oggetti, ogni `pinned` è un booleano (altrimenti non si sa quali voci entrano), almeno una
  voce ha `pinned: true`, e ogni voce pinned ha `url`, `snippet_sha256`, `content_kind`, `retrieved_at` tutti
  stringhe. Non richiedo forma esadecimale o canonica: la radice si calcola sui byte come portati (§5.3.3). Altrimenti
  il membro resta assente. Tocca la tabella delle note: per `evi-content-kind-absent-when-pinned-rejects` e
  `evi-snippet-sha256-absent-when-pinned-rejects` la radice resta assente (manca o è null un membro del preimage), come
  spiega babyblueviper1; la mia regola l'ho scritta da §5.3.3 (il preimage lega quei quattro membri), ma l'ho scritta
  DOPO aver letto la sua spiegazione — non è un accordo indipendente.
- **L4 — vettori di sola radice.** Undici vettori non hanno `evidence_set` nell'input e portano `computed` (chiavi
  `root*`/`normative_root`). Lettura: per questi il checker calcola solo `evidence_root` (§5.3.3) sulle voci con
  `pinned: true` di: `set_1` e `set_2` (e se le due radici sono uguali), la lista se l'input è una lista, `sources`,
  oppure `[entry]`. Non chiamo `resolve()`. La classificazione usa la FORMA dell'input e la presenza di `computed`, non
  il `designation`.
- **L5 — contenuto detenuto (§5.4.1(d)).**
  - `verifier_holds_bytes_for: null` → il verificatore non detiene nulla.
  - `verifier_holds_bytes_for` (URL o lista di URL) con `content_matches: true` → per ogni voce pinned con quell'url,
    `held_sha256[i] = snippet_sha256` della voce (l'input dichiara che i byte detenuti hanno quel digest).
  - `verifier_holds_bytes_for` (URL) con `verifier_recomputed_sha256` → `held_sha256[i]` = quel valore per la voce
    pinned con quell'url.
- **L6 — ricevuta senza evidence_set.** `{"receipt_shape": "no evidence_set member present"}` → payload `{}`.
- **L7 — membri `note`** dentro l'input: ignorati (non sono membri del payload).
- **L8 — più condizioni.** Il checker riporta l'INSIEME completo; il conteggio regola-harness e quello stretto si
  calcolano dopo, nel runner di confronto (PREREG, Metro 2–3).
