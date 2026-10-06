# Scelte che il testo della -03 (5a718639288a) lascia aperte — scritte PRIMA di leggere i vettori

Ogni voce: cosa dice il testo, cosa ho scelto, cosa cambierebbe l'altra lettura. Marcate `# CHOICE n` in es_check.py.

1. **snippet_sha256_not_lowercase_hex64 su una voce con `pinned` non booleano.** §5.3.2 elenca la condizione come
   controllo sul valore («a non-null value that is not exactly 64 lowercase hexadecimal characters»); la regola del
   controllo intero (§5.4.1(a)) sopprime solo ciò che *prende in input* un membro fallito. Scelto: la valuto comunque.
2. **`unpinned_reason` presente su una voce pinned.** Nessuna condizione definita. Scelto: nessuna segnalazione.
3. **`resource_sha256: null`.** Il membro è «string, OPTIONAL», «when present MUST be 64 hex»; la regola full_resource
   dice «non-null resource_sha256». Scelto: null = presente e non hex64 (→ resource_sha256_not_lowercase_hex64), ma non
   fa scattare resource_sha256_present_for_full_resource. Per content_kind il testo dichiara null ≡ assente; per
   resource_sha256 no.
4. **Codifica di `evidence_root`.** Mai fissata in modo normativo (§5.3.1 «string»; l'esempio §5.6 mostra «c9f2...»).
   Scelto: 64 caratteri esadecimali minuscoli del digest radice. Due implementazioni che scelgono diversamente
   (maiuscolo, base64) danno root_not_recomputable_from_sources a vicenda.
5. **`source_count` / `pinned_count` non interi** (stringa, float `2.0`, booleano). Nessun controllo di tipo definito.
   Scelto: un valore non intero non può «equal» len(sources) → *_mismatch; un booleano non è un intero.
6. **`fully_pinned` derivato dai conteggi DICHIARATI o REALI.** §5.3.1: «true if and only if pinned_count equals
   source_count»; il paragrafo sul fallback parla di «operand for any check in this section». Scelto: operandi
   (dichiarati se presenti). Conseguenza: un source_count sbagliato produce ANCHE fully_pinned_mismatch; con la lettura
   «reali» no. È un caso in cui il testo non fissa l'insieme riportato.
7. **`fully_pinned` non booleano.** Scelto: «differs from this derivation» → fully_pinned_mismatch.
8. **evidence_root presente/assente: confronto con pinned_count dichiarato o con le voci.** Il testo dice «with no
   pinned entry» / «with at least one pinned entry». Scelto: le voci reali (soppresso se un `pinned` è invalido).
9. **Quali fallimenti sopprimono duplicate_bound_tuple e set_retrieved_at_not_bytewise_least.** Il testo dice «type or
   form check». Scelto: sopprimono solo i fallimenti di tipo/forma (url, retrieved_at, pinned, snippet hex64,
   content_kind fuori dominio, NUL, voce non oggetto), NON quelli di coerenza (snippet_sha256_absent_when_pinned,
   content_kind_present_when_unpinned…).
10. **Set-level `retrieved_at` non stringa o in forma non canonica.** Nessuna condizione di forma a livello set.
    Scelto: set_retrieved_at_not_bytewise_least (confronto di byte fallito).

## Correzione 26/09 (dopo una revisione indipendente)
5. «nessun controllo di tipo definito» era FALSO: §5.3.1 dichiara source_count e pinned_count «(integer)». Manca solo una condizione nominata per il tipo sbagliato.
