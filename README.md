# capture_udp_sig

Снимает живой UDP (DNS, QUIC, SIP, STUN…) и пишет **банк сигнатур** для панели amnezia-wg-easy: CPS `I1–I5` в одном JSON.

Панель **не** вызывает этот модуль в runtime — только подкладывает готовый файл в `/opt/amnezia/awg/signatures.json`.

## Формат для панели (drop-in)

```json
{
  "version": 1,
  "target": 100,
  "profiles": {
    "dns": {
      "1": { "i1": "<b 0x…>", "i2": "…", "i3": "…", "i4": "…", "i5": "…" },
      "2": { "i1": "<b 0x…>" }
    },
    "quic_browser": {
      "1": { "i1": "<b 0x…>", "i2": "…", "i3": "…", "i4": "…", "i5": "…" }
    }
  }
}
```

Ключи `"1"`, `"2"`, … — варианты одного протокола. В каждом варианте только слоты с реальным `<b 0x…>` (partial OK, нужен минимум `i1`).

## Сборка банка (основной режим)

Нужны **Git** и **Docker**.

```powershell
git clone https://github.com/ne-tort/capture_udp_sig.git
cd capture_udp_sig
poetry install --only main
poetry run python scripts/build_signature_bank.py --out output/signatures.json --target 10
```

```bash
git clone https://github.com/ne-tort/capture_udp_sig.git
cd capture_udp_sig
poetry install --only main
poetry run python scripts/build_signature_bank.py --out output/signatures.json --target 10
```

| Параметр | Назначение |
|----------|------------|
| `--target N` | Желаемое число итераций на протокол (статичные протоколы часто дают 1) |
| `--out PATH` | Выходной JSON (= файл панели) |
| `--profile dns` | Только указанные протоколы (повторяемо) |
| `--no-build` | Не пересобирать Docker-образы |

## В панель

Скопируйте результат в volume:

```text
/opt/amnezia/awg/signatures.json
```

Перезапуск контейнера не обязателен (панель перечитывает по mtime). Если у клиента был номер варианта, которого больше нет — панель назначит новый при следующем конфиге/refresh.

## Один профиль (отладка)

```powershell
.\scripts\docker_capture.ps1 dns
# → output/live_dns.json
```

В банк это не пишет автоматически — для панели используйте `build_signature_bank.py`.
