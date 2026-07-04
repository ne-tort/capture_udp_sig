# WSL2: live capture не работает без mirrored networking

Проверка: `tcpdump -i any` пишет **0 bytes** pcap при curl — трафик не виден в WSL2 NAT.

## Исправление (Windows, один раз)

Создайте/отредактируйте `%UserProfile%\.wslconfig`:

```ini
[wsl2]
networkingMode=mirrored
dnsTunneling=true
```

Затем в PowerShell **от администратора**:

```powershell
wsl --shutdown
```

Перезапустите WSL и снова:

```bash
SIGNATURE_LAB_SUDO_PW=112233 bash scripts/wsl_setup.sh
bash scripts/wsl_capture.sh quic_browser 90
```

## Без mirrored mode

- **dry-run** (фикстуры): `poetry run python audit_capture.py --dry-run --strict` — quic I1–I5 OK
- **live**: только нативный Linux / VM, не WSL2 NAT
