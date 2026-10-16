<# School CyberWatch - start backend startup script
   Usage:
     powershell -ExecutionPolicy Bypass -File start-backend.ps1
#>

$ErrorActionPreference = "Stop"

$repoRoot = "c:/Users/Dell/Downloads/SchoolCyberwatch-main/SchoolCyberwatch-main"
$backendDir = Join-Path $repoRoot "Backend"
$mvn = Join-Path $backendDir "../tools/apache-maven-3.9.9/bin/mvn"
$logFile = Join-Path $backendDir "backend-run.log"

# Copy env.example.properties to env.properties if env.properties is missing/empty
$envProps = Join-Path $backendDir "env.properties"
$envExample = Join-Path $backendDir "env.example.properties"
if (-not (Test-Path $envProps) -or (Get-Item $envProps).Length -eq 0) {
  if (Test-Path $envExample) {
    Copy-Item $envExample $envProps -Force
    Write-Host "[startup] Copied env.example.properties -> env.properties"
  }
}

# Load environment variables from env.properties (so Spring Boot picks them up)
if (Test-Path $envProps) {
  Get-Content $envProps | ForEach-Object {
    if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$') {
      $name = $Matches[1]
      $value = $Matches[2]
      # strip surrounding quotes
      if ($value -match '^["\'](.*)["\']$') { $value = $Matches[1] }
      Set-Item -Path "Env:$name" -Value $value -Force
      Write-Host "[startup] Set $name"
    }
  }
  Write-Host "[startup] Loaded env.properties"
}

# Start the Spring Boot app in the background
Write-Host "[startup] Starting backend..."
$proc = Start-Process -FilePath "java" -ArgumentList "-jar", "$(Join-Path $backendDir 'target/backend-0.0.1-SNAPSHOT.jar')" -PassThru -NoNewWindow

# Wait for the jar, then start via maven spring-boot:run if needed
Write-Host "[startup] Done initializing. Backend log: $logFile"
