# capture_udp_sig

Снимает живой UDP-трафик (DNS, QUIC, SIP, STUN и др.) и превращает его в параметры **I1–I5** для обфускации **AmneziaWG 2** — CPS-строки вида `<b 0x…>`, которые подставляются в конфиг клиента/сервера.

## Установка

```bash
poetry install                  # dns, sip, dtls, ntp — без браузера
poetry install --with browser   # + quic, stun, webrtc (Chromium/Playwright)
```

## Основные команды

```bash
# что доступно в этой среде
python -m siglab list --available-only

# один режим → строки I1..I5 в терминал (.conf формат)
python -m siglab capture --profile dns --format conf

# все доступные режимы → JSON для wg-easy панели
python -m siglab batch --out signatures.json --format panel
```

**Live через Docker** (Windows/Linux, browser и tcpdump внутри образа, на хосте Poetry не нужен):

```powershell
python -m siglab capture --docker --profile quic_browser --out output/live.json
# или
.\scripts\docker_live.ps1 quic_browser
```

## Без браузера

Если Playwright не ставили (или в Docker-образе панели):

```bash
export CAPTURE_NO_BROWSER=1   # алиас: SIGLAB_NO_BROWSER=1
```

Browser-режимы (`quic*`, `stun*`, `webrtc`) просто не попадут в список — остальное работает.

## Полезные опции

| Флаг | Зачем |
|------|--------|
| `--dry-run` | Тест без сети (фикстуры) |
| `--timeout N` | Таймаут захвата, сек |
| `--format panel` | Плоский JSON для wg-easy |
| `--format conf` | Строки `I1 = …` для .conf |
| `--merge-into path/signatures.json` | Добавить один профиль в существующий файл |

## wg-easy

Репозиторий подключается как submodule `capture_udp_sig/`. Панель вызывает `python -m siglab` через `src/lib/siglabBridge.js`. Переменная `CAPTURE_UDP_SIG_ROOT` — если submodule лежит не в стандартном месте.
