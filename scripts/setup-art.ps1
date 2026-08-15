Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
$dl = "C:\Users\analyst\Downloads"

Invoke-WebRequest -Uri http://10.10.10.1:8000/invoke-atomicredteam.zip -OutFile "$dl\iart.zip"
Invoke-WebRequest -Uri http://10.10.10.1:8000/atomics.zip -OutFile "$dl\atomics.zip"
Invoke-WebRequest -Uri http://10.10.10.1:8000/powershell-yaml.zip -OutFile "$dl\psyaml.zip"

Expand-Archive "$dl\iart.zip" -DestinationPath C:\AtomicRedTeam -Force
Expand-Archive "$dl\atomics.zip" -DestinationPath C:\AtomicRedTeam -Force
$mod = "C:\Program Files\WindowsPowerShell\Modules\powershell-yaml"
Expand-Archive "$dl\psyaml.zip" -DestinationPath $mod -Force
if (Test-Path "$mod\powershell-yaml") {
  Move-Item "$mod\powershell-yaml\*" $mod -Force -ErrorAction SilentlyContinue
  Remove-Item "$mod\powershell-yaml" -Recurse -Force
}

Import-Module powershell-yaml -ErrorAction Stop
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force -ErrorAction Stop
$global:PSDefaultParameterValues = @{"Invoke-AtomicTest:PathToAtomicsFolder"="C:\AtomicRedTeam\atomic-red-team\atomics"}

if (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue) {
  Write-Host "`nREADY - Invoke-AtomicTest available." -ForegroundColor Green
} else {
  Write-Host "`nFAILED - module did not load." -ForegroundColor Red
}
