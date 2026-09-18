# run-as-admin.ps1
# Ejecutar este script como administrador para agregar exclusiones en Windows Defender

$projectPath = "C:\Users\jpom1\OneDrive\Escritorio\PROYECTOS\jack-sparrow"
$tempPath = "C:\Users\jpom1\AppData\Local\Temp"

Write-Host "Agregando exclusiones en Windows Defender..." -ForegroundColor Cyan

try {
    Add-MpPreference -ExclusionPath $projectPath
    Write-Host "[OK] Excluida: $projectPath" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] No se pudo excluir $projectPath" -ForegroundColor Red
    Write-Host "  Ejecuta este script como Administrador" -ForegroundColor Yellow
}

try {
    Add-MpPreference -ExclusionPath $tempPath
    Write-Host "[OK] Excluida: $tempPath" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] No se pudo excluir $tempPath" -ForegroundColor Red
}

Write-Host ""
Write-Host "Verificando exclusiones actuales..." -ForegroundColor Cyan
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath

Write-Host ""
Write-Host "Listo! Reinicia tu terminal para que los cambios surtan efecto." -ForegroundColor Green
