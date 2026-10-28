$ErrorActionPreference = 'Stop'
$repoUrl = 'https://github.com/ALIZZZALI/ALI-VPN-Panel-Vercel.git'

Write-Host ''
Write-Host 'ALI VPN Panel - upload clean Vercel bundle to GitHub' -ForegroundColor Cyan
Write-Host 'This uploads the extracted source to your existing repository.'
Write-Host 'No API key, .env file, panel database, or backup should be included.'
Write-Host ''

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'Git was not found. Install Git for Windows, reopen PowerShell, and run this script again.'
}

$defaultZip = Join-Path $PSScriptRoot 'ALI-VPN-Panel-Vercel-Ready.zip'
$zipPath = Read-Host "Full path to ALI-VPN-Panel-Vercel-Ready.zip [default: $defaultZip]"
if ([string]::IsNullOrWhiteSpace($zipPath)) { $zipPath = $defaultZip }
$zipPath = [Environment]::ExpandEnvironmentVariables($zipPath.Trim().Trim('"'))
if (-not (Test-Path -LiteralPath $zipPath -PathType Leaf)) { throw "ZIP not found: $zipPath" }

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    $names = @($archive.Entries | ForEach-Object { $_.FullName.Replace('\','/') })
    $required = @('ALI-VPN-Panel/app.py','ALI-VPN-Panel/index.html','ALI-VPN-Panel/vercel.json','ALI-VPN-Panel/requirements.txt')
    foreach ($name in $required) {
        if ($names -notcontains $name) { throw "Unexpected ZIP: required file is missing: $name" }
    }
    $unsafe = @($names | Where-Object {
        $_ -match '(^|/)\.env$' -or
        $_ -match '(^|/)panel-data\.json(\.bak)?$' -or
        $_ -match '\.(pem|key|p12|pfx|sqlite|db)$' -or
        $_ -match '(^|/)(id_rsa|credentials\.json|secrets\.json)$'
    })
    if ($unsafe.Count -gt 0) { throw "Upload stopped: sensitive-looking file(s) found: $($unsafe -join ', ')" }
} finally { $archive.Dispose() }

$work = Join-Path ([System.IO.Path]::GetTempPath()) ('ali-vpn-github-' + [guid]::NewGuid().ToString('N'))
$extract = Join-Path $work 'extract'
$clone = Join-Path $work 'repo'
New-Item -ItemType Directory -Path $extract | Out-Null

try {
    Expand-Archive -LiteralPath $zipPath -DestinationPath $extract -Force
    $source = Join-Path $extract 'ALI-VPN-Panel'
    if (-not (Test-Path -LiteralPath $source -PathType Container)) { throw 'Could not find the project folder inside the ZIP.' }

    Write-Host 'Cloning the GitHub repository...' -ForegroundColor Yellow
    git clone $repoUrl $clone
    if ($LASTEXITCODE -ne 0) { throw 'Git clone failed.' }

    Write-Host 'Copying clean project files...' -ForegroundColor Yellow
    Get-ChildItem -LiteralPath $source -Force | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $clone -Recurse -Force
    }

    # Remove this one-time helper from the cloned project before committing.
    $helperInClone = Join-Path $clone 'Push-ALI-VPN-Panel-To-GitHub.ps1'
    if (Test-Path -LiteralPath $helperInClone) { Remove-Item -LiteralPath $helperInClone -Force }

    # Final guard: do not commit local-only data or real environment files.
    $blocked = @(
        Get-ChildItem -LiteralPath $clone -Force -Recurse -File | Where-Object {
            $_.Name -eq '.env' -or $_.Name -match '^panel-data\.json(\.bak)?$' -or $_.Extension -in @('.pem','.key','.p12','.pfx','.sqlite','.db')
        }
    )
    if ($blocked.Count -gt 0) {
        throw "Upload stopped; review these file(s) before continuing: $(( $blocked | ForEach-Object FullName) -join ', ')"
    }

    Push-Location $clone
    try {
        git add -A
        if ($LASTEXITCODE -ne 0) { throw 'git add failed.' }
        $changes = git status --porcelain
        if (-not $changes) {
            Write-Host 'No changes to upload; the repository already matches this ZIP.' -ForegroundColor Green
            return
        }
        if (-not (git config user.name)) {
            $gitName = Read-Host 'Name to record on the commit'
            if ([string]::IsNullOrWhiteSpace($gitName)) { throw 'A Git commit name is required.' }
            git config user.name $gitName
        }
        if (-not (git config user.email)) {
            $gitEmail = Read-Host 'Email to record on the commit (can be a GitHub noreply address)'
            if ([string]::IsNullOrWhiteSpace($gitEmail)) { throw 'A Git commit email is required.' }
            git config user.email $gitEmail
        }
        git commit -m 'Deploy clean ALI VPN Panel on Vercel'
        if ($LASTEXITCODE -ne 0) { throw 'git commit failed.' }
        Write-Host 'Pushing to GitHub (Git may ask you to sign in)...' -ForegroundColor Yellow
        git push origin HEAD:main
        if ($LASTEXITCODE -ne 0) { throw 'git push failed. Check GitHub sign-in and repository permissions, then run the script again.' }
    } finally { Pop-Location }

    Write-Host ''
    Write-Host 'Upload completed.' -ForegroundColor Green
    Write-Host $repoUrl
    Write-Host 'Next: import this repository in Vercel and configure Upstash + environment variables.'
} finally {
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}
