<# Launch School CyberWatch backend with env.properties sourced.
   Usage: powershell -ExecutionPolicy Bypass -File launch-backend.ps1
#>
$ErrorActionPreference = "Stop"

$repoRoot = "c:/Users/Dell/Downloads/SchoolCyberwatch-main/SchoolCyberwatch-main"
$backendDir = Join-Path $repoRoot "Backend"
$mvn = Join-Path $backendDir "../tools/apache-maven-3.9.9/bin/mvn"
$logFile = Join-Path $backendDir "backend-run.log"

# Load env.properties into the environment (so Spring Boot reads ${DB_PASSWORD:...} etc.)
$envProps = Join-Path $backendDir "env.properties"
if (Test-Path $envProps) {
  Get-Content $envProps | ForEach-Object {
    if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$') {
      $name = $Matches[1]
      $value = $Matches[2]
      if ($value -match '^["\'](.*)["\']$') { $value = $Matches[1] }
      Set-Item -Path "Env:$name" -Value $value -Force
    }
  }
  Write-Host "[launch] Loaded env.properties"
} else {
  Write-Host "[launch] WARNING: env.properties not found; using current env"
}

# Write an empty marker so we can confirm the process started
Set-Content -Path (Join-Path $backendDir "start-marker.txt") -Value "[launch] env loaded at $(Get-Date)"

# Run Maven spring-boot:run, redirecting all output to the log
Write-Host "[launch] Starting: $mvn spring-boot:run"
& $mvn spring-boot:run > $logFile 2>&1
$exitCode = $LASTEXITCODE
Write-Host "[launch] Maven exited with code $exitCode"
exit $exitCode
