@echo off
chcp 65001 > nul
color 0A
cls

echo.
echo ╔════════════════════════════════════════════════════╗
echo ║     INSTALADOR - NILKAS POS v1.0                   ║
echo ║     Sistema de Punto de Venta                      ║
echo ╚════════════════════════════════════════════════════╝
echo.

REM Verificar si se ejecuta como administrador
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ⚠️  ADVERTENCIA: Este instalador debe ejecutarse como Administrador
    echo.
    pause
    exit /b 1
)

echo ✅ Ejecutando como Administrador...
echo.

REM Crear carpeta de instalación
set "INSTALL_DIR=%ProgramFiles%\Nilkas POS"
set "DATA_DIR=%APPDATA%\nilkas"

echo 📂 Ruta de instalación: %INSTALL_DIR%
echo 💾 Ruta de datos: %DATA_DIR%
echo.

REM Crear directorios
if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
    echo ✅ Carpeta de instalación creada
) else (
    echo ⚠️  La carpeta ya existe. Se actualizará...
)

if not exist "%DATA_DIR%" (
    mkdir "%DATA_DIR%"
    echo ✅ Carpeta de datos creada
)

echo.
echo 📋 Copiando archivos...

REM Copiar los archivos necesarios
for %%F in (nilkas.exe) do (
    if exist "%%F" (
        copy "%%F" "%INSTALL_DIR%\" /Y > nul
        echo ✅ Copiado: %%F
    ) else (
        echo ❌ ERROR: No se encontró %%F
    )
)

REM Copiar archivos de soporte
if exist "data" (
    xcopy "data" "%INSTALL_DIR%\data" /E /Y /I > nul
    echo ✅ Archivos de datos copiados
)

echo.
echo 🔗 Creando accesos directos...

REM Crear acceso directo en escritorio
set "DESKTOP=%USERPROFILE%\Desktop"
set "SHORTCUT=%DESKTOP%\Nilkas POS.lnk"

powershell -Command "$WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%SHORTCUT%'); $Shortcut.TargetPath = '%INSTALL_DIR%\nilkas.exe'; $Shortcut.WorkingDirectory = '%INSTALL_DIR%'; $Shortcut.IconLocation = '%INSTALL_DIR%\nilkas.exe'; $Shortcut.Save()" 2>nul

if exist "%SHORTCUT%" (
    echo ✅ Acceso directo creado en escritorio
) else (
    echo ⚠️  No se pudo crear acceso directo en escritorio
)

REM Crear acceso directo en inicio rápido (Menú Inicio)
set "START_MENU=%APPDATA%\Microsoft\Windows\Start Menu\Programs"
if not exist "%START_MENU%\Nilkas" mkdir "%START_MENU%\Nilkas"

powershell -Command "$WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%START_MENU%\Nilkas\Nilkas POS.lnk'); $Shortcut.TargetPath = '%INSTALL_DIR%\nilkas.exe'; $Shortcut.WorkingDirectory = '%INSTALL_DIR%'; $Shortcut.IconLocation = '%INSTALL_DIR%\nilkas.exe'; $Shortcut.Save()" 2>nul

if exist "%START_MENU%\Nilkas\Nilkas POS.lnk" (
    echo ✅ Acceso directo creado en Menú Inicio
) else (
    echo ⚠️  No se pudo crear acceso directo en Menú Inicio
)

echo.
echo ✨ INSTALACIÓN COMPLETADA
echo.
echo 📌 Próximos pasos:
echo    1. Busca "Nilkas POS" en el Menú Inicio o tu Escritorio
echo    2. Haz clic en el icono para ejecutar la aplicación
echo    3. Completa la configuración inicial
echo    4. ¡Comienza a usar tu sistema POS!
echo.
echo 📖 Para más información, consulta README.md
echo.
pause
