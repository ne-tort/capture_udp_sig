# capture_udp_sig

Снимает живой UDP-трафик (DNS, QUIC, SIP, STUN и др.) и превращает его в параметры **I1–I5** для обфускации **AmneziaWG 2** — CPS-строки вида `<b 0x…>` для конфига клиента/сервера.

В **[amnezia-wg-easy](https://github.com/ne-tort/amnezia-wg-easy)** подключается как submodule `capture_udp_sig/`; панель вызывает `python -m siglab` для `signatures.json`. Ниже — автономный запуск: клон → Docker → готовый JSON с I-слотами. Нужны только **Git** и **Docker Desktop** (или Docker на Linux), Python/Poetry на хосте не нужны.

## Быстрый захват (Docker)

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

Скрипт соберёт образ, сделает live-захват и выведет `output/live_dns.json` с I1–I5. Первый запуск дольше (сборка образа ~1–3 мин), повторные — быстрее.

Другие режимы — тот же скрипт, другой профиль:

```powershell
.\scripts\docker_capture.ps1 quic_browser
.\scripts\docker_capture.ps1 sip_multi
```

Строки для `.conf`: возьми `i1`…`i5` из JSON и подставь как `I1 = …`, `I2 = …` в конфиг AmneziaWG 2.

## wg-easy submodule

```bash
git clone --recurse-submodules https://github.com/ne-tort/amnezia-wg-easy.git
cd amnezia-wg-easy/capture_udp_sig
./scripts/docker_capture.sh dns
```

Нестандартный путь к репозиторию: `CAPTURE_UDP_SIG_ROOT`.

## Локально без Docker (Poetry)

```bash
cd capture_udp_sig
poetry install                  # dns, sip, dtls, ntp
poetry install --with browser   # + quic, stun, webrtc
python -m siglab capture --profile dns --format conf
python -m siglab batch --out signatures.json --format panel
```

Без браузера (образ панели wg-easy): `CAPTURE_NO_BROWSER=1` — режимы `quic*`, `stun*`, `webrtc` отключаются, остальное работает.

## Опции

| Параметр | Пример | Зачем |
|----------|--------|--------|
| профиль | `dns`, `quic_browser`, `sip_multi` | Протокол/режим захвата |
| timeout | `.\scripts\docker_capture.ps1 dns 20` | Таймаут, сек |
| `--dry-run` | `python -m siglab capture --profile dns --dry-run` | Тест без сети (Poetry) |
| `--format panel` | `siglab batch …` | JSON для wg-easy |
| `--merge-into` | `siglab capture … --merge-into signatures.json` | Добавить профиль в файл |
