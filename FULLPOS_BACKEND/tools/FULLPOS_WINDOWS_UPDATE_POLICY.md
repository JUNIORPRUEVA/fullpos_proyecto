# Política de actualización de FullPOS Windows

La migración `20260612223000_add_app_update_releases` crea la tabla administrada
por Prisma. El endpoint público es:

```text
GET /api/app-updates/fullpos/windows
```

Un administrador autenticado con rol `admin` u `owner` puede crear o actualizar
la política con:

```text
PUT /api/app-updates/fullpos/windows
```

Ejemplo para la primera actualización real:

```json
{
  "projectCode": "fullpos",
  "platform": "windows",
  "version": "1.0.2",
  "buildNumber": 6,
  "minimumSupportedVersion": "1.0.1",
  "minimumSupportedBuild": 5,
  "mandatory": false,
  "enabled": true,
  "installerUrl": "https://github.com/JUNIORPRUEVA/fullpos-releases/releases/download/v1.0.2/FullPOS-Setup.exe",
  "installerFilename": "FullPOS-Setup.exe",
  "installerSizeBytes": 236522251,
  "sha256": "REEMPLAZAR_CON_EL_SHA256_DE_64_CARACTERES_DEL_INSTALADOR_FINAL",
  "releaseTitle": "FullPOS v1.0.2",
  "releaseNotes": [
    "Mejoras de estabilidad.",
    "Correcciones de sincronización.",
    "Mejoras generales de seguridad."
  ],
  "publishedAt": "2026-06-12T22:00:00Z"
}
```

No envíe este ejemplo sin reemplazar `installerSizeBytes` y `sha256`. Cada
recompilación cambia ambos valores. `installer/build_release.ps1` genera el
SHA-256 del archivo final `FullPOS-Setup.exe`.
