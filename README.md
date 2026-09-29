# ChaD-Sence — serwer lokalny

Testowy backend (Python + FastAPI + SQLite) dla 3 aplikacji: Pacjent, Specjalista, Opiekun.
Pełna instrukcja konfiguracji krok po kroku jest w głównym pliku `SETUP.md` w repozytorium —
tu jest tylko szybki start.

## Szybki start

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

`--host 0.0.0.0` jest kluczowe — dzięki temu telefon w tej samej sieci WiFi
też się połączy (nie tylko `localhost` na komputerze).

## Automatyczne otwieranie strony z logami przy starcie

Zaraz po uruchomieniu serwer sam otwiera w domyślnej przeglądarce stronę
`/dashboard`. Na samej górze tej strony jest wyraźny baner z adresem, pod
którym serwer nasłuchuje (np. `http://192.168.1.23:8000`) — to jest adres,
który trzeba wpisać w każdej z 3 aplikacji na telefonie. Adres IP jest
wykrywany automatycznie (nie trzeba go nigdzie wpisywać ręcznie), a port —
odczytywany z faktycznie działającego serwera, więc baner jest poprawny
niezależnie od tego, jaki `--port` podano przy starcie.

Jeśli nie chcesz, żeby przeglądarka otwierała się sama (np. na serwerze bez
GUI), ustaw zmienną środowiskową `CHAD_SENCE_NO_BROWSER=1` przed uruchomieniem:

```bash
CHAD_SENCE_NO_BROWSER=1 uvicorn main:app --host 0.0.0.0 --port 8000
```

Zmienna `PORT` (jeśli ustawiona) jest używana tylko przy budowaniu adresu w
banerze — faktyczny port nasłuchiwania zawsze ustawia się przez `--port` w
komendzie uvicorn.

## Sprawdzenie, czy działa

W przeglądarce na komputerze: http://localhost:8000/health
Powinno zwrócić: `{"status":"ok","time":"..."}`

Interaktywna dokumentacja API (przydatna do ręcznego testowania): http://localhost:8000/docs

## Dashboard: adres IP, logi żądań i podpięte urządzenia (w czasie rzeczywistym)

http://localhost:8000/dashboard (albo `http://<IP_komputera>:8000/dashboard` z dowolnego
urządzenia w sieci) — otwiera się automatycznie przy starcie serwera (patrz wyżej) i
pokazuje trzy sekcje:

1. **Baner z adresem serwera** — na samej górze, duży i czytelny, żeby łatwo było go
   przepisać do konfiguracji aplikacji na telefonie.
2. **Logi żądań** — na żywo, każde żądanie HTTP trafiające do serwera (metoda, ścieżka,
   kod odpowiedzi, adres IP nadawcy, czas trwania), najnowsze na górze. Przydatne do
   szybkiego sprawdzenia, czy dana apka faktycznie się komunikuje z serwerem i czy nie
   dostaje błędów. Trzyma w pamięci ostatnie 300 żądań (surowe dane: `/api/logs`).
3. **Podpięte urządzenia** — lista wszystkich urządzeń, które kiedykolwiek odezwały się
   do serwera: rolę (pacjent/specjalista/opiekun), Device ID, model telefonu, adres IP,
   kiedy ostatnio nawiązały kontakt, i czy są "online" (kontakt w ciągu ostatnich 60 s).

Cała strona odświeża się sama co 2 sekundy (zwykły `fetch()` w JS, bez WebSocketów —
prościej i równie "na żywo" dla potrzeb testów).

**Dlaczego nie ma prawdziwego adresu MAC:** od Androida 6.0 system celowo blokuje
aplikacjom odczyt realnego MAC-adresu karty WiFi — zwraca zawsze fałszywą wartość
`02:00:00:00:00:00`, a od Androida 10 dodatkowo losuje inny MAC dla każdej sieci
(ochrona prywatności, nie da się tego obejść bez roota). Dashboard pokazuje to pole
jako informację "niedostępny", a jako realny identyfikator urządzenia w sieci używa
**adresu IP** — ten serwer widzi bezpośrednio z połączenia TCP, więc jest zawsze
prawdziwy — w połączeniu z Device ID (stały UUID generowany przy pierwszym uruchomieniu
każdej z 3 apek).

Surowe dane w JSON, jeśli wolisz je przetwarzać programowo: `/api/devices`.

## Statystyki pacjenta: średnia z 24h, przeliczana co godzinę

Aplikacja Pacjenta wysyła paczkę danych co 15 minut (patrz `SyncWorker` w apce). Serwer
nie pokazuje jednak specjaliście/opiekunowi surowej, ostatniej paczki — zamiast tego
liczy **średnią z ostatnich 24 godzin** dla każdej metryki (aktywność telefonu, używanie
aplikacji, aktywność ruchowa, aktywność w pomieszczeniu, blokowanie/odblokowanie,
połączenia, SMS) i do tego **% zmiany względem poprzednio przeliczonej średniej**.

Przeliczenie nowej średniej następuje **najwyżej raz na godzinę** na pacjenta:

- Za każdym razem, gdy specjalista lub opiekun otworzy dane pacjenta
  (`GET /patients/{id}/data`), serwer sprawdza wiek ostatniej zapisanej migawki
  (`patient_stats_snapshots`) i przelicza nową tylko, jeśli minęła już ponad godzina —
  więc przeglądanie danych nie wpływa na częstotliwość przeliczeń.
- Niezależnie od tego, w tle działa pętla (`asyncio`, co 5 minut), która sama sprawdza
  wszystkich pacjentów i dolicza świeżą migawkę, gdy zrobi się nieaktualna — dzięki temu
  statystyki są aktualne nawet, jeśli akurat nikt nie zagląda na ekran danych.

Wynik w odpowiedzi API: `stats_computed_at` (kiedy policzono) oraz dla każdej metryki pola
`{metryka}_avg` (średnia) i `{metryka}_pct` (procent zmiany; `null`, gdy nie ma jeszcze
poprzedniej migawki do porównania — np. przy pierwszym pomiarze pacjenta).

## Domyślne konto specjalisty (do testów)

- ID: `spec001`
- Hasło: `test1234`

## Baza danych

Plik `chad_sence.db` (SQLite) tworzy się automatycznie przy pierwszym uruchomieniu w tym
samym katalogu (albo pod ścieżką ze zmiennej `CHAD_SENCE_DB_PATH` — patrz niżej). Żeby
zresetować wszystkie dane — po prostu go usuń i uruchom serwer ponownie.

**Dane behawioralne (`behavior_data`) i migawki statystyk (`patient_stats_snapshots`)
nigdy nie są nadpisywane ani kasowane** — każdy nowy pakiet danych od pacjenta i każde
przeliczenie średniej to zawsze nowy wiersz (`INSERT`), więc pełna historia pomiarów
zostaje w bazie na zawsze (przydatne do pracy magisterskiej — można w każdej chwili
odtworzyć cały przebieg w czasie, nie tylko ostatni stan). Aktualizowane w miejscu są
tylko pola **bieżącego stanu**, które z natury mają jedną aktualną wartość: profil
pacjenta (imię, limit opiekunów, ostatnia synchronizacja), status wiadomości
(`pending` → `seen`) i wpis urządzenia na dashboardzie (`ostatnio widziane`) — to
świadomy wybór, a nie utrata danych: gdyby np. adres IP telefonu zmieniał się przy
każdym połączeniu i za każdym razem dopisywał nowy wiersz, tabela `devices` rosłaby
w nieskończoność bez żadnej wartości analitycznej.

## Wdrożenie na serwerze zewnętrznym (żeby imitować prawdziwy backend, nie tylko lokalną sieć WiFi)

Domyślnie serwer zakłada, że telefon i komputer są w tej samej sieci WiFi (`SETUP.md`).
Żeby zamiast tego mieć serwer dostępny z internetu (np. do pokazania promotorowi bez
kombinowania z siecią), trzeba hosta z **trwałym dyskiem** — zwykły darmowy hosting bez
tej opcji kasuje plik `chad_sence.db` przy każdym restarcie/redeployu kontenera, bo jego
system plików jest tymczasowy.

Najprościej: **[Railway](https://railway.com)** ma gotowy szablon `FastAPI + SQLite`
z podpiętym trwałym wolumenem ([oficjalny przykład](https://railway.com/deploy/official-fastapi-backend-sqlite)),
więc obsługa woluminów jest tam standardowym, przetestowanym rozwiązaniem. Nowe konto
dostaje 30-dniowy okres próbny z $5 kredytu bez podawania karty, potem plan Hobby to
$5/mies. (niewielki ruch testowy tej apki mieści się w kredycie z zapasem). Alternatywy
z podobnym mechanizmem trwałych wolumenów: **[Fly.io](https://fly.io/learn/python-hosting/)**
(płatne od ok. $2/mies. za mały kontener, do tego wolumen) — dobre, jeśli wolisz Dockera
i CLI zamiast panelu webowego.

### Kroki (na przykładzie Railway)

1. Wrzuć zawartość folderu `server/` do repozytorium GitHub (albo użyj Railway CLI,
   które umie wdrożyć folder bez gita — `railway up`).
2. W Railway: **New Project → Deploy from GitHub repo**, wskaż to repozytorium.
3. Dodaj **Volume** (zakładka "Volumes" w serwisie) — punkt montowania np. `/data`.
4. Ustaw zmienne środowiskowe serwisu:
   ```
   CHAD_SENCE_DB_PATH=/data/chad_sence.db
   CHAD_SENCE_PUBLIC_URL=https://<twoja-domena>.up.railway.app
   ```
   (dokładną domenę Railway pokaże po pierwszym deployu, w zakładce "Settings → Networking
   → Generate Domain" — wtedy wróć i dopisz ją jako `CHAD_SENCE_PUBLIC_URL`, potem redeploy).
5. Ustaw komendę startową (Settings → Deploy → Start Command):
   ```
   uvicorn main:app --host 0.0.0.0 --port $PORT
   ```
6. Po wdrożeniu wejdź na `https://<twoja-domena>.up.railway.app/dashboard` — baner na
   górze pokaże teraz Twój publiczny adres (dzięki `CHAD_SENCE_PUBLIC_URL`) zamiast
   lokalnego IP, bo automatyczne wykrywanie IP nie ma sensu na hostingu w chmurze.
7. W każdej z 3 aplikacji na telefonie w polu adresu serwera wpisz **pełny adres z
   `https://`**, np. `https://chadsence-production.up.railway.app` — apki już to
   obsługują (jeśli podasz adres bez `http://`/`https://`, sama dokleja `http://`, więc
   dla wersji w chmurze zawsze podawaj pełny adres z `https://`). Telefon i serwer nie
   muszą już być w tej samej sieci WiFi — apka zadziała z dowolnego miejsca z internetem.

**Uwaga o `CHAD_SENCE_NO_BROWSER`:** na serwerze w chmurze automatyczne otwieranie
przeglądarki i tak się nie uda (brak GUI) — ustawienie `CHAD_SENCE_PUBLIC_URL` wyłącza tę
próbę automatycznie, więc nie trzeba dodatkowo ustawiać `CHAD_SENCE_NO_BROWSER`.

Sources:
- [Deploy & Host official-fastapi-backend-sqlite | Railway](https://railway.com/deploy/official-fastapi-backend-sqlite)
- [Railway Pricing](https://railway.com/pricing)
- [Best Python Hosting Providers in 2026 (Compared) — Fly.io](https://fly.io/learn/python-hosting/)
