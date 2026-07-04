# capture_udp_sig

Снимает живой UDP-трафик (DNS, QUIC, SIP, STUN и др.) и превращает его в параметры **I1–I5** для обфускации **AmneziaWG 2** — CPS-строки вида `<b 0x…>` для конфига клиента/сервера.

В **[amnezia-wg-easy](https://github.com/ne-tort/amnezia-wg-easy)** подключается как submodule `capture_udp_sig/`; панель сама вызывает `python -m siglab` для генерации `signatures.json`. Клон с сабмодулем: `git clone --recurse-submodules …`. Отдельный checkout — ниже; переменная `CAPTURE_UDP_SIG_ROOT`, если путь нестандартный.

## Установка

```bash
cd capture_udp_sig   # или корень submodule в wg-easy
poetry install                  # dns, sip, dtls, ntp — без браузера
poetry install --with browser   # + quic, stun, webrtc (Chromium/Playwright)
```

## Основные команды

```bash
python -m siglab list --available-only
python -m siglab capture --profile dns --format conf
python -m siglab batch --out signatures.json --format panel   # JSON для панели wg-easy
```

**Live через Docker** (browser и tcpdump в образе, на хосте Poetry не нужен):

```powershell
python -m siglab capture --docker --profile quic_browser --out output/live.json
# или .\scripts\docker_live.ps1 quic_browser
```

## Без браузера

Если Playwright не ставили (типично для Docker-образа панели):

```bash
export CAPTURE_NO_BROWSER=1   # алиас: SIGLAB_NO_BROWSER=1
```

Режимы `quic*`, `stun*`, `webrtc` не попадут в список — остальное работает.

## Полезные опции

| Флаг | Зачем |
|------|--------|
| `--dry-run` | Тест без сети (фикстуры) |
| `--timeout N` | Таймаут захвата, сек |
| `--format panel` | Плоский JSON для wg-easy |
| `--format conf` | Строки `I1 = …` для .conf |
| `--merge-into path/signatures.json` | Добавить один профиль в существующий файл |
