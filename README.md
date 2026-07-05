# capture_udp_sig

Снимает живой UDP-трафик (DNS, QUIC, SIP, STUN и др.) и превращает его в параметры **I1–I5** для обфускации **AmneziaWG 2** — CPS-строки вида `<b 0x…>` для конфига клиента/сервера.

В **[amnezia-wg-easy](https://github.com/ne-tort/amnezia-wg-easy)** подключается как submodule `capture_udp_sig/`; панель вызывает `python -m siglab` для `signatures.json`. Ниже — автономный запуск: клон → Docker → готовый JSON с I-слотами. Нужны только **Git** и **Docker Desktop** (или Docker на Linux).

## Быстрый захват одного профиля (Docker)

**Windows (PowerShell):**

```powershell
git clone https://github.com/ne-tort/capture_udp_sig.git
cd capture_udp_sig
.\scripts\docker_capture.ps1 dns
```

**Linux / macOS:**

```bash
git clone https://github.com/ne-tort/capture_udp_sig.git
cd capture_udp_sig
chmod +x scripts/docker_capture.sh
./scripts/docker_capture.sh dns
```

Результат: `output/live_dns.json` с полями `i1`…`i5`. Браузерные профили (`quic*`, `stun*`, `webrtc`) — тот же скрипт:

```powershell
.\scripts\docker_capture.ps1 quic_browser
```

## Пакетная генерация (N итераций, все протоколы)

Один JSON-файл с нумерованными итерациями по каждому протоколу. Можно прервать и продолжить тем же `--out`.

```powershell
git clone https://github.com/ne-tort/capture_udp_sig.git
cd capture_udp_sig
poetry install --only main
poetry run python scripts/build_signature_bank.py --out output/signatures.json --target 100
```

```bash
git clone https://github.com/ne-tort/capture_udp_sig.git
cd capture_udp_sig
poetry install --only main
poetry run python scripts/build_signature_bank.py --out output/signatures.json --target 100
```

| Параметр | Пример | Назначение |
|----------|--------|------------|
| `--target` | `10`, `100`, `1000` | Запрошенное число итераций на протокол |
| `--out` | `output/signatures.json` | Файл результата (resume-safe) |
| `--profile` | `dns` (повторяемо) | Только указанные протоколы |
| `--no-build` | — | Не пересобирать Docker-образы |

Протоколы с реальной вариативностью (`dns`, `dtls`) набирают до `--target` итераций. Остальные дают один уникальный вариант; при дубликате i1 итерации для протокола останавливаются. При 429 протокол пропускается.

**Формат `output/signatures.json`:**

```json
{
  "version": 1,
  "target": 100,
  "profiles": {
    "dns": {
      "1": { "i1": "<b 0x...>", "i2": "<b 0x...>", "i3": "...", "i4": "...", "i5": "..." },
      "2": { "i1": "<b 0x...>" }
    },
    "quic_browser": {
      "1": { "i1": "<b 0x...><rc 8><t><r 100>", "i2": "..." }
    }
  }
}
```

Ключи итераций — строки `"1"`, `"2"`, …; внутри только `i1`–`i5` в CPS-формате. Для `.conf` AmneziaWG: `I1 = <b 0x…>` (заглавные ключи).

## wg-easy submodule

```bash
git clone --recurse-submodules https://github.com/ne-tort/amnezia-wg-easy.git
cd amnezia-wg-easy/capture_udp_sig
./scripts/docker_capture.sh dns
```

Нестандартный путь: `CAPTURE_UDP_SIG_ROOT`.

## Локально без Docker (Poetry)

```bash
cd capture_udp_sig
poetry install                  # dns, sip, dtls, ntp
poetry install --with browser   # + quic, stun, webrtc
python -m siglab capture --profile dns --format conf
```

## Опции

| Параметр | Пример | Зачем |
|----------|--------|--------|
| профиль | `dns`, `quic_browser`, `sip_multi` | Протокол захвата |
| timeout | `.\scripts\docker_capture.ps1 dns 20` | Таймаут, сек |
| `--dry-run` | `siglab capture --profile dns --dry-run` | Тест без сети (Poetry) |
| `--format panel` | `siglab batch …` | JSON для wg-easy |
