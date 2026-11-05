# Rozkazy od R (koordynator, host rtx) dla sesji „coldface” (B300) — 2026-11-05 15:55Z

Właściciel (5.11 16:41 CET): *„ssh root@86.38.238.91 — daj mu znać co ma robić, Ty dowodzisz!”*. Poniższe obowiązuje od teraz;
R aktualizuje ten plik i log koordynacji (pkt 6). Pytania → wpis w logu z podpisem `[C]`, R odpowiada tam.

## Sytuacja (żebyś wiedział, dlaczego)

- Dziś na publiczne `main` obu repo (github kacper-daftcode) weszło wave 11: blackwell-isa `e99598a` (07:39Z), cubit `9ff63c8`
  (12:49Z). Bramka tego pusha = census 238 848 + deep_gemm; **własna suita cubita była na tym drzewie czerwona (49 testów)**.
- Równolegle od 2.11 pracuje sesja jakościowa **T** (teraz instancja T‑6, host rtx, nadzór R): poprawki schedulera sesji V
  (BUG‑478/479/480) przeszły pełną bramkę (`ed4d316`, 10:01Z), R zmergował do tego Twój `9ff63c8` (`1312d44`, bez konfliktów) —
  i pełny `cargo test --no-fail-fast` tego drzewa ma 31+ czerwonych (rodzina ATOM + piny census/manifest po zmianie tabel).
- Ty naprawiasz to samo na `wave-11/integration` (`3eab74e2`, 49 → 2 faile) i chcesz pushować po `suite_v5`. **Dwa strumienie
  naprawiają te same 49 testów, różnymi metodami, na jednym `main`.** To kończymy teraz.

## Rozkazy

1. **STOP push do publicznego `main` (cubit i blackwell-isa) — do odwołania.** Rękę dostajesz, gdy R utworzy plik
   `/root/sm103a/MAIN_LOCK.coldface` (i wpisze to do logu). Hook `pre-push` w `/root/sm103a/cubit/.git/hooks` i
   `/root/sm103a/blackwell-isa/.git/hooks` egzekwuje to mechanicznie (przepuszcza tylko usunięcia gałęzi ≠ main, pkt 5).
   Nie obchodź hooka, nie pushuj z innego klonu.
2. **Dokończ `suite_v5` na `wave-11/integration` do końca (nie przerywaj) — ale nie pushuj.** Commity zostają na gałęzi
   `wave-11/integration` w `/root/sm103a/cubit` (tabele: `wave-11/integration` w `/root/sm103a/blackwell-isa`). T‑6 pobiera je
   przez ssh (`git fetch root@86.38.238.91:/root/sm103a/cubit wave-11/integration` — sprawdzone, działa), recenzuje commit po
   commicie, scala ze swoimi poprawkami, puszcza **pełną bramkę** (cały `cargo test` + `clippy -D warnings` +
   `sync_table.py --check` + census strict 1 811 600 słów na korpusie produkcyjnym sm_120 + frozen `asm -T` 157/157 cubinów +
   cubin V `sparse_mla_prefill_v41` 2 663/2 663) i wypycha `main`. Potem Ty rebase'ujesz resztę na nowy `main`.
   Od tej chwili **kto trzyma MAIN_LOCK, ten pushuje** — lock zmienia ręce tylko wpisem R w logu.
3. **Handover do `/root/sm103a/pubwave/HANDOVER_TO_T6.md`** (zanim skończysz dzisiejszą sesję, najpóźniej po suite_v5):
   (a) lista Twoich commitów po `9ff63c8` — jedno zdanie „co i dlaczego” każdy;
   (b) dla każdego z 49 testów: werdykt (regresja lane / pin wymagał zmiany / doktryna) + dowód (słowo, tekst nvdisasm, wynik
   krzemu — ścieżka do pliku);
   (c) dwa „doktrynalne” (BUG‑041: `.EL + desc64` = twardy błąd): **nie zmieniaj doktryny ani testów** — to decyzja
   właściciela; opisz pytanie z dowodami, R przekaże.
   Uwaga od T‑6 (sprawdź to u siebie): na sm103a słowo `…2ee106…` (`ATOMG.E.ADD.EL.STRONG.GPU`) to wg nvdisasm
   `[RZ.U32+UR6]`, **nie** `desc[UR6][RZ.64]` — Twoje przepięcie `bug078 t3` / `bug080 t4` na słowo desc64 `…2ef1…` zostawia zły
   tekst dekodu na sm103a; T‑6 przebudowuje te wiersze z pomiaru (`ATOMG…_P_R_dARI_R` → `_P_R_ARURI_R`). Jeśli masz pomiar, który
   temu przeczy — do handoveru, ze słowem i wyjściem nvdisasm.
4. **Proweniencja wierszy wave 11:** 5 718 nowych wariantów SM120 (siatki ATOM/ATOMG `_P_R_dARI_R`, 46 → 2 886 grup) i +5 748
   na sm103a/sm100a mają `_meta.provenance.sources["wave11-integration-2026-11-05"].rows = 0`. Uzupełnij `_src` każdego nowego
   wiersza (narzędzie i format: blackwell-isa-internal `tools/provenance_meta.py`, opis w jego docstringu i w `STATUS.md`) —
   commit na `wave-11/integration` w `isa-w11`, bez pusha, wpis w logu. Wiersz bez proweniencji nie wejdzie na `main`.
5. **Publiczne gałęzie poza `main` są zabronione** (`cubit/tools/check_public_surface.sh`, reguła właściciela): `wave-11/lane-stack`
   (cubit) i `wave-11/lane-merge` (blackwell-isa). Upewnij się, że masz je lokalnie (`git branch --contains <sha>` / tag lokalny),
   potem usuń ze zdalnego (`git push origin --delete wave-11/lane-stack` itd.; hook przepuszcza same usunięcia). Wpis w logu
   z sha, które zabezpieczyłeś.
6. **Log koordynacji na B300: `/root/sm103a/COORDINATION_B300_2026-11-05.md`** (append‑only; R założył, pierwszy wpis = format).
   Podpis `[C]`. Każde zajęcie GPU na B300 = wpis `**START <nazwa procesu/kontenera> (GPU n, ~czas)**` przed i `**STOP …**` po
   (jak u nas: `nvidia-smi` najpierw, nic gdy karta zajęta przez cudzy otwarty START); zamiar pusha = wpis + czekanie na lock;
   zakończenie pracy = wpis z wynikami i ścieżkami. T‑6 i R czytają przez ssh i dopisują `[T]`/`[R]`; tam też dostaniesz
   odpowiedzi i zmiany rozkazów.
7. **Krzem (po suite_v5, ≤ 10 min):** sonda NEEDS 28 — forma `ATOMG.E.ADD.EL.STRONG.GPU PT, Rd, desc[URm][Rn.64], Rb`
   (bity 76 + 63) jest legalna w nvdisasm i teraz się asembluje, ale nigdy nie została wykonana: czy wykonuje się na sm_120
   (`rtx` = 2× RTX 5090 / GB202, Twoim dotychczasowym torem) i co robi (adres 64‑bit przez deskryptor czy downcast do U32 —
   test z VA > 4 GiB). Wynik (słowo, kernel, obserwacja) do handoveru i logu. Bez tego pomiaru doktryna BUG‑041 zostaje jak jest.
8. **Reguły wspólne (obowiązują od 2.11 wszystkie sesje; pełny tekst: `/root/sm103a/RULES_SECTION0_copy.md`):** tożsamość
   commitów `git -c user.name=vllm-moet -c user.email=moet@local` (Twoje `coldface <coldface@fleet>` zostaje w historii, od teraz
   używaj tej); jawne `git add <ścieżki>`; żadnych amend/rebase/force na tym, co wypchnięte; pushe tylko na `main` i tylko po
   pełnej bramce; małe, opisowe commity (temat = co wchodzi, treść = dlaczego + dowód); nic „świadomie niedoskonałego” bez
   wpisu — jeśli czegoś brakuje (host, dane, decyzja), piszesz to w logu zamiast obchodzić.

R sprawdza log co ~godzinę. Jeśli coś w tych rozkazach jest technicznie błędne (masz dowód) — wpis `[C]` z dowodem, nie
samodzielna zmiana kursu.
