<# School CyberWatch - start both backend and frontend
   Usage:
     powershell -ExecutionPolicy Bypass -File start-both.ps1
#>

$ErrorActionPreference = "Stop"

$repoRoot = "c:/Users/Dell/Downloads/SchoolCyberwatch-main/SchoolCyberwatch-main"
$backendDir  = Join-Path $repoRoot "Backend"
$frontendDir = Join-Path $repoRoot "Frontend"
$mvn          = Join-Path $backendDir "../tools/apache-maven-3.9.9/bin/mvn"
$logBackend   = Join-Path $backendDir "backend-run.log"
$logFrontend  = Join-Path $frontendDir "frontend-run.log"

# --- Backend environment (from env.properties if present) ---
$envProps = Join-Path $backendDir "env.properties"
if (-not (Test-Path $envProps) -or (Get-Item $envProps).Length -eq 0) {
  if (Test-Path (Join-Path $backendDir "env.example.properties")) {
    Copy-Item (Join-Path $backendDir "env.example.properties") $envProps -Force
    Write-Host "[startup] Copied env.example.properties -> env.properties"
  }
}

if (Test-Path $envProps) {
  Get-Content $envProps | ForEach-Object {
    if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$') {
      $name  = $Matches[1]
      $value = $Matches[2]
      if ($value -match '^["\'](.*)["\']$') { $value = $Matches[1] }
      Set-Item -Path "Env:$name" -Value $value -Force
    }
  }
}

# --- Frontend environment ---
$frontendEnv = Join-Path $frontendDir ".env"
if (-not (Test-Path $frontendEnv)) {
  if (Test-Path (Join-Path $frontendDir ".env.example")) {
    Copy-Item (Join-Path $frontendDir ".env.example") $frontendEnv -Force
    Write-Host "[startup] Copied .env.example -> .env"
  }
}

# --- Start backend (mvn spring-boot:run) in the background ---
Write-Host "[startup] Starting backend (mvn spring-boot:run)..."
$backendProc = Start-Process -FilePath "powershell" -ArgumentList "-ExecutionPolicy", "Bypass", "-NoExit", "-File", "-",
  "-Command", "`$env:JAVA_HOME='C:/Program Files/Java/jdk-21.0.12'; & `"$mvn`" spring-boot:run > `"$logBackend`" 2>&1; exit `$LASTEXITCODE" -PassThru -NoNewWindow

# Wait a moment, then check if backend started
Start-Sleep -Seconds 3
if (Test-Path $logBackend) {
  Get-Content $logBackend | Select-Object -First 30
}

# --- Start frontend (npm run dev) in the background ---
Write-Host "[startup] Starting frontend (npm run dev)..."
$frontendProc = Start-Process -FilePath "powershell" -ArgumentList "-ExecutionPolicy", "Bypass", "-NoExit", "-File", "-",
  "-Command", "`$env:NODE_ENV='development'; & `"$env:APPDATAnpm\node_modules\npm\cli.js`" --prefix `"$frontendDir`" run dev > `"$logFrontend`" 2>&1; exit `$LASTEXITCODE" -PassThru -NoNewWindow

Write-Host "[startup] Both servers started. Press Ctrl+C to stop."
Write-Host "[startup] Backend log: $logBackend"
Write-Host "[startup] Frontend log: $logFrontend"
