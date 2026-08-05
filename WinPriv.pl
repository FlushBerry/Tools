#!/usr/bin/perl
# perlpeas.pl - Windows Privilege Escalation Enumeration
# Sans cmd.exe, sans powershell.exe - Perl pur + WMI + Registry

use strict;
use warnings;
use Win32::OLE qw(in);
use Win32::OLE::Const;
use Win32::TieRegistry (Delimiter => '/', ArrayValues => 1);

$Win32::OLE::Warn = 0;
$| = 1;

my $OUT;
my $outfile = 'C:\\Users\\Public\\perlpeas_report.txt';
open($OUT, '>', $outfile) or die "Cannot write $outfile: $!";

sub p { my $s = shift; print $s; print $OUT $s; }
sub section { p("\n" . "="x70 . "\n== $_[0]\n" . "="x70 . "\n"); }
sub sub_s   { p("\n--- $_[0] ---\n"); }
sub kv      { p(sprintf("  %-30s : %s\n", $_[0], $_[1] // '')); }

p("PerlPEAS - Privilege Escalation Enum (pure Perl)\n");
p("Report: $outfile\n");
p("Date: " . localtime() . "\n");

my $wmi = Win32::OLE->GetObject("winmgmts://./root/cimv2");
unless($wmi) { p("[!] WMI unavailable - limited enum\n"); }

#=============================================================
section("1. SYSTEM INFO");
#=============================================================
if($wmi) {
    my $os = $wmi->ExecQuery("SELECT * FROM Win32_OperatingSystem");
    foreach my $o (in $os) {
        kv("OS",            $o->{Caption});
        kv("Version",       $o->{Version});
        kv("Build",         $o->{BuildNumber});
        kv("Arch",          $o->{OSArchitecture});
        kv("InstallDate",   $o->{InstallDate});
        kv("LastBoot",      $o->{LastBootUpTime});
        kv("SystemDir",     $o->{SystemDirectory});
        kv("Organization",  $o->{Organization});
        kv("RegisteredUser",$o->{RegisteredUser});
    }
    my $cs = $wmi->ExecQuery("SELECT * FROM Win32_ComputerSystem");
    foreach my $c (in $cs) {
        kv("Hostname",   $c->{Name});
        kv("Domain",     $c->{Domain});
        kv("Manufacturer", $c->{Manufacturer});
        kv("Model",      $c->{Model});
        kv("TotalRAM_MB", int(($c->{TotalPhysicalMemory}||0)/1024/1024));
    }
}

#=============================================================
section("2. CURRENT USER & PRIVILEGES");
#=============================================================
kv("USERNAME",    $ENV{USERNAME});
kv("USERDOMAIN",  $ENV{USERDOMAIN});
kv("USERPROFILE", $ENV{USERPROFILE});
kv("HOMEDRIVE",   $ENV{HOMEDRIVE});
kv("LOGONSERVER", $ENV{LOGONSERVER});

if($wmi) {
    sub_s("Local Groups of current user");
    my $u = $ENV{USERNAME};
    my $grps = $wmi->ExecQuery(
      "SELECT * FROM Win32_GroupUser");
    foreach my $g (in $grps) {
        my $pc = $g->{PartComponent} || '';
        my $gc = $g->{GroupComponent} || '';
        if($pc =~ /Name="\Q$u\E"/i) {
            if($gc =~ /Name="([^"]+)"/) { p("  Member of: $1\n"); }
        }
    }
}

#=============================================================
section("3. USERS & ADMINS");
#=============================================================
if($wmi) {
    sub_s("Local Users");
    my $users = $wmi->ExecQuery("SELECT * FROM Win32_UserAccount WHERE LocalAccount=True");
    foreach my $u (in $users) {
        p(sprintf("  %-20s SID=%s Disabled=%s Lockout=%s PwdReq=%s PwdExp=%s\n",
            $u->{Name}, $u->{SID}, $u->{Disabled}?1:0,
            $u->{Lockout}?1:0, $u->{PasswordRequired}?1:0,
            $u->{PasswordExpires}?1:0));
    }
    sub_s("Local Groups");
    my $groups = $wmi->ExecQuery("SELECT * FROM Win32_Group WHERE LocalAccount=True");
    foreach my $g (in $groups) {
        p(sprintf("  %-25s : %s\n", $g->{Name}, $g->{Description}||''));
    }
}

#=============================================================
section("4. UAC / LSA / AUTH CONFIG  [CRITIQUE]");
#=============================================================
my $reg = $Win32::TieRegistry::Registry;

my @uac_keys = (
    ['HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/System/EnableLUA','EnableLUA (0=UAC off=PRIVESC)'],
    ['HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/System/ConsentPromptBehaviorAdmin','ConsentPrompt'],
    ['HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/System/LocalAccountTokenFilterPolicy','LocalAccountTokenFilterPolicy (1=PTH possible)'],
    ['HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/System/FilterAdministratorToken','FilterAdministratorToken'],
    ['HKLM/SYSTEM/CurrentControlSet/Control/Lsa/LmCompatibilityLevel','LmCompatibilityLevel (<3=weak)'],
    ['HKLM/SYSTEM/CurrentControlSet/Control/Lsa/NoLMHash','NoLMHash'],
    ['HKLM/SYSTEM/CurrentControlSet/Control/Lsa/RestrictAnonymous','RestrictAnonymous'],
    ['HKLM/SYSTEM/CurrentControlSet/Control/Lsa/RestrictAnonymousSAM','RestrictAnonymousSAM'],
    ['HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/System/DisableCAD','DisableCAD'],
);
foreach my $k (@uac_keys) {
    my $v = $reg->{$k->[0]};
    if(ref $v eq 'ARRAY') { $v = $v->[0]; }
    kv($k->[1], defined $v ? $v : '(not set)');
}

sub_s("AlwaysInstallElevated [CRITIQUE si =1]");
my $aie1 = $reg->{'HKLM/SOFTWARE/Policies/Microsoft/Windows/Installer/AlwaysInstallElevated'};
my $aie2 = $reg->{'HKCU/SOFTWARE/Policies/Microsoft/Windows/Installer/AlwaysInstallElevated'};
$aie1 = $aie1->[0] if ref $aie1 eq 'ARRAY';
$aie2 = $aie2->[0] if ref $aie2 eq 'ARRAY';
kv("HKLM AlwaysInstallElevated", $aie1 // '0');
kv("HKCU AlwaysInstallElevated", $aie2 // '0');
if(($aie1//0) == 1 && ($aie2//0) == 1) {
    p("  [!!!] PRIVESC : AlwaysInstallElevated ACTIF -> MSI en SYSTEM\n");
}

#=============================================================
section("5. AUTOLOGON / WINLOGON CREDS  [CRITIQUE]");
#=============================================================
my $wl = 'HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon/';
for my $v (qw(DefaultUserName DefaultDomainName DefaultPassword AutoAdminLogon
              AltDefaultUserName AltDefaultPassword)) {
    my $val = $reg->{$wl.$v};
    $val = $val->[0] if ref $val eq 'ARRAY';
    kv($v, $val // '(not set)');
    if($v =~ /Password/i && defined $val && $val ne '') {
        p("  [!!!] PRIVESC : password en clair dans registre !\n");
    }
}

#=============================================================
section("6. SERVICES - unquoted paths / weak perms  [CRITIQUE]");
#=============================================================
if($wmi) {
    my $svc = $wmi->ExecQuery("SELECT Name,DisplayName,PathName,StartMode,State,StartName FROM Win32_Service");
    my $count = 0; my $unq = 0;
    foreach my $s (in $svc) {
        $count++;
        my $path = $s->{PathName} || '';
        # unquoted path with spaces
        if($path =~ /^([A-Za-z]:\\[^"]*\s[^"]*\.exe)/i && $path !~ /^"/) {
            $unq++;
            p("  [UNQUOTED] $s->{Name} ($s->{StartMode}) : $path\n");
            p("             RunAs: $s->{StartName}\n");
        }
    }
    kv("Total services", $count);
    kv("Unquoted paths", $unq);

    sub_s("Services running as SYSTEM/LocalSystem");
    my $svc2 = $wmi->ExecQuery("SELECT Name,PathName,StartName,State FROM Win32_Service WHERE StartName='LocalSystem'");
    my $n=0;
    foreach my $s (in $svc2) {
        next unless $s->{State} eq 'Running';
        $n++;
        p(sprintf("  %-35s %s\n", $s->{Name}, $s->{PathName}||''));
        last if $n > 40;
    }

    sub_s("Services in non-standard paths (writable dirs?)");
    my $svc3 = $wmi->ExecQuery("SELECT Name,PathName FROM Win32_Service");
    foreach my $s (in $svc3) {
        my $path = $s->{PathName} || '';
        $path =~ s/^"([^"]+)".*/$1/;
        $path =~ s/\s.*// if $path !~ /"/;
        if($path && $path !~ /^C:\\Windows/i && $path !~ /Program Files/i && -f $path) {
            my @st = stat($path);
            my $dir = $path; $dir =~ s|\\[^\\]+$||;
            p(sprintf("  %-30s %s\n", $s->{Name}, $path));
            # test écriture dans le dossier
            my $testf = "$dir\\.perlpeas_$$";
            if(open(my $t, '>', $testf)) { close $t; unlink $testf;
                p("    [!!!] DOSSIER WRITABLE -> service replace possible !\n");
            }
        }
    }
}

#=============================================================
section("7. SCHEDULED TASKS (via WMI + XML)");
#=============================================================
eval {
    my $ts = Win32::OLE->new('Schedule.Service');
    $ts->Connect();
    my $folder = $ts->GetFolder('\\');
    sub _walk {
        my ($f) = @_;
        my $tasks = $f->GetTasks(1);
        foreach my $t (in $tasks) {
            my $xml = $t->Xml || '';
            my $user = '';
            if($xml =~ m|<UserId>([^<]+)</UserId>|) { $user = $1; }
            if($xml =~ m|<RunLevel>([^<]+)</RunLevel>|) { $user .= " [$1]"; }
            my $cmd = '';
            if($xml =~ m|<Command>([^<]+)</Command>|) { $cmd = $1; }
            my $args = '';
            if($xml =~ m|<Arguments>([^<]+)</Arguments>|) { $args = $1; }
            p(sprintf("  %-40s User=%s\n", $t->Path, $user));
            p(sprintf("    CMD: %s %s\n", $cmd, $args)) if $cmd;
            if($cmd && -f $cmd) {
                my $dir = $cmd; $dir =~ s|\\[^\\]+$||;
                my $tf = "$dir\\.pp_$$";
                if(open(my $x,'>',$tf)) { close $x; unlink $tf;
                    p("    [!!!] Task binary dir writable: $dir\n");
                }
            }
        }
        foreach my $sf (in $f->GetFolders(0)) { _walk($sf); }
    }
    _walk($folder);
};
p("  [!] Task Scheduler COM unavailable: $@\n") if $@;

#=============================================================
section("8. INSTALLED SOFTWARE (Uninstall keys)");
#=============================================================
for my $hive ('HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/',
              'HKLM/SOFTWARE/Wow6432Node/Microsoft/Windows/CurrentVersion/Uninstall/') {
    my $k = $reg->{$hive};
    next unless $k;
    foreach my $sub (keys %$k) {
        my $app = $k->{$sub};
        next unless ref $app;
        my $n = $app->{'/DisplayName'};
        $n = $n->[0] if ref $n eq 'ARRAY';
        my $v = $app->{'/DisplayVersion'};
        $v = $v->[0] if ref $v eq 'ARRAY';
        next unless $n;
        p(sprintf("  %-50s %s\n", $n, $v||''));
    }
}

#=============================================================
section("9. PATH DIRS - writable check  [CRITIQUE si writable]");
#=============================================================
my @paths = split /;/, ($ENV{PATH}||'');
foreach my $p (@paths) {
    next unless $p;
    $p =~ s/\s+$//;
    if(-d $p) {
        my $tf = "$p\\.pp_test_$$";
        if(open(my $x, '>', $tf)) { close $x; unlink $tf;
            p("  [WRITABLE] $p\n");
        } else {
            p("  [ok]       $p\n");
        }
    } else {
        p("  [missing]  $p\n");
    }
}

#=============================================================
section("10. CREDENTIALS HUNTING - fichiers sensibles");
#=============================================================
my @targets = (
    'C:\\Windows\\Panther\\Unattend.xml',
    'C:\\Windows\\Panther\\Unattended.xml',
    'C:\\Windows\\Panther\\Unattend\\Unattend.xml',
    'C:\\Windows\\System32\\sysprep\\sysprep.xml',
    'C:\\Windows\\System32\\sysprep\\sysprep.inf',
    'C:\\Windows\\System32\\sysprep.inf',
    'C:\\unattend.xml',
    'C:\\Windows\\debug\\NetSetup.log',
    'C:\\Windows\\repair\\sam',
    'C:\\Windows\\repair\\system',
    'C:\\Windows\\System32\\config\\RegBack\\SAM',
    'C:\\Windows\\System32\\config\\RegBack\\SYSTEM',
    'C:\\Windows\\System32\\config\\SAM',
    'C:\\Windows\\iis6.log',
    'C:\\Windows\\system32\\inetsrv\\config\\applicationHost.config',
    "$ENV{USERPROFILE}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt",
);
foreach my $f (@targets) {
    if(-e $f) {
        my $sz = -s $f;
        p("  [FOUND] $f ($sz bytes)\n");
        if(-r $f) { p("          -> READABLE !\n"); }
    }
}

sub_s("Recherche récursive *password*/*.config dans C:\\Users\\Public + Temp");
my @scan = ('C:\\Users\\Public', $ENV{TEMP}||'C:\\Windows\\Temp');
foreach my $root (@scan) {
    next unless -d $root;
    _scan($root, 0);
}
sub _scan {
    my ($dir, $depth) = @_;
    return if $depth > 4;
    opendir(my $dh, $dir) or return;
    while(my $e = readdir($dh)) {
        next if $e eq '.' || $e eq '..';
        my $full = "$dir\\$e";
        if(-d $full) { _scan($full, $depth+1); }
        elsif($e =~ /pass|cred|secret|\.kdbx$|\.config$|web\.config|\.xml$|unattend/i) {
            p("  [INTEREST] $full\n");
        }
    }
    closedir($dh);
}

#=============================================================
section("11. NETWORK INFO");
#=============================================================
if($wmi) {
    my $nic = $wmi->ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True");
    foreach my $n (in $nic) {
        p("  " . ($n->{Description}||'') . "\n");
        my $ips = $n->{IPAddress};
        if(ref $ips eq 'ARRAY') { p("    IPs: " . join(", ", @$ips) . "\n"); }
        my $gw  = $n->{DefaultIPGateway};
        if(ref $gw eq 'ARRAY')  { p("    GW : " . join(", ", @$gw) . "\n"); }
        my $dns = $n->{DNSServerSearchOrder};
        if(ref $dns eq 'ARRAY') { p("    DNS: " . join(", ", @$dns) . "\n"); }
        kv("    MAC", $n->{MACAddress});
    }
    sub_s("TCP Listening ports (via netstat file? on non, via WMI Win32_... -> limité)");
    # WMI n'expose pas netstat; on liste les connexions via Win32_Process owners
}

#=============================================================
section("12. SHARES");
#=============================================================
if($wmi) {
    my $sh = $wmi->ExecQuery("SELECT * FROM Win32_Share");
    foreach my $s (in $sh) {
        p(sprintf("  %-20s %-40s %s\n", $s->{Name}, $s->{Path}||'', $s->{Description}||''));
    }
}

#=============================================================
section("13. DRIVERS (3rd party - potentiel exploit)");
#=============================================================
if($wmi) {
    my $drv = $wmi->ExecQuery("SELECT Name,DisplayName,PathName,State,StartMode FROM Win32_SystemDriver WHERE State='Running'");
    my $n=0;
    foreach my $d (in $drv) {
        my $p = $d->{PathName}||'';
        next if $p =~ /Windows\\System32\\(drivers\\)?[a-z0-9]+\.sys$/i && $p !~ /3rd|vendor/i;
        # heuristique: tout ce qui n'est pas dans System32 ou signé microsoft
        next if $p =~ /Microsoft/i;
        $n++;
        p(sprintf("  %-30s %s\n", $d->{Name}, $p));
        last if $n > 30;
    }
}

#=============================================================
section("14. STARTUP (registry Run keys)");
#=============================================================
my @run = (
    'HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Run',
    'HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/RunOnce',
    'HKLM/SOFTWARE/Wow6432Node/Microsoft/Windows/CurrentVersion/Run',
    'HKCU/SOFTWARE/Microsoft/Windows/CurrentVersion/Run',
    'HKCU/SOFTWARE/Microsoft/Windows/CurrentVersion/RunOnce',
);
foreach my $rk (@run) {
    my $k = $reg->{$rk};
    next unless $k;
    p("  [$rk]\n");
    foreach my $v (keys %$k) {
        next unless $v =~ m|^/|;
        my $val = $k->{$v};
        $val = $val->[0] if ref $val eq 'ARRAY';
        p(sprintf("    %-25s = %s\n", $v, $val||''));
        # extract binaire
        if($val && $val =~ /^"?([A-Za-z]:\\[^"]+\.exe)/) {
            my $bin = $1;
            if(-f $bin) {
                my $d = $bin; $d =~ s|\\[^\\]+$||;
                my $tf = "$d\\.pp_$$";
                if(open(my $x,'>',$tf)) { close $x; unlink $tf;
                    p("      [!!!] binaire dir WRITABLE: $d\n");
                }
            }
        }
    }
}

#=============================================================
section("15. ENVIRONMENT VARIABLES");
#=============================================================
foreach my $k (sort keys %ENV) {
    p(sprintf("  %-25s = %s\n", $k, $ENV{$k}));
}

#=============================================================
section("16. PATCHES / HOTFIXES");
#=============================================================
if($wmi) {
    my $hf = $wmi->ExecQuery("SELECT HotFixID,InstalledOn,Description FROM Win32_QuickFixEngineering");
    my @list;
    foreach my $h (in $hf) {
        push @list, sprintf("  %-15s %-20s %s", $h->{HotFixID}||'', $h->{InstalledOn}||'', $h->{Description}||'');
    }
    p(join("\n", @list) . "\n");
    kv("Total hotfixes", scalar @list);
    if(@list < 10) { p("  [!] Peu de patchs -> machine potentiellement vulnérable à exploits kernel\n"); }
}

#=============================================================
section("17. FIREWALL STATUS");
#=============================================================
eval {
    my $fw = Win32::OLE->new('HNetCfg.FwPolicy2');
    for my $profile (1, 2, 4) {  # Domain, Private, Public
        my $name = {1=>'Domain',2=>'Private',4=>'Public'}->{$profile};
        kv("FW $name enabled", $fw->FirewallEnabled($profile) ? 'YES' : 'NO');
    }
};
p("  [!] FW COM unavailable: $@\n") if $@;

#=============================================================
section("18. AV / DEFENDER");
#=============================================================
eval {
    my $sc = Win32::OLE->GetObject("winmgmts://./root/SecurityCenter2");
    if($sc) {
        my $av = $sc->ExecQuery("SELECT * FROM AntiVirusProduct");
        foreach my $a (in $av) {
            kv("AV", $a->{displayName});
            kv("  state (hex)", sprintf("0x%X", $a->{productState}||0));
        }
    }
};

#=============================================================
section("19. RDP / WINRM");
#=============================================================
my $rdp = $reg->{'HKLM/SYSTEM/CurrentControlSet/Control/Terminal Server/fDenyTSConnections'};
$rdp = $rdp->[0] if ref $rdp eq 'ARRAY';
kv("RDP enabled (0=yes)", $rdp // '?');
my $nla = $reg->{'HKLM/SYSTEM/CurrentControlSet/Control/Terminal Server/WinStations/RDP-Tcp/UserAuthentication'};
$nla = $nla->[0] if ref $nla eq 'ARRAY';
kv("RDP NLA", $nla // '?');

#=============================================================
section("20. POTENTIAL PRIVESC SUMMARY");
#=============================================================
p("  -> Vérifier [UNQUOTED] services\n");
p("  -> Vérifier [WRITABLE] directories dans services/PATH/Run keys\n");
p("  -> Vérifier AlwaysInstallElevated si =1\n");
p("  -> Vérifier DefaultPassword Winlogon\n");
p("  -> Vérifier Unattend.xml trouvés\n");
p("  -> Vérifier hotfixes manquants -> exploits kernel publics\n");
p("  -> Vérifier UAC (EnableLUA=0)\n");

close($OUT);
p("\n[+] Rapport complet: $outfile\n");
