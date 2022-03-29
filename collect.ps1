#  collect.ps1
#  Bitcoin Artefact Collector
#  Written by Arran Holmes 40454196
# 
$version = "0.1.4"

# robocopy is used to copy files to avoid changing last accessed 
timestamps
<# You may need to enable powershell scripts with "set-executionpolicy 
Bypass -Scope Process" #>


<# 
    Taken from https://community.idera.com/database-tools/powershell/ 
powertips/b/tips/posts/searching-files-using-index-search 
    Searches though the windows file index, allows for very fast searching 
of keywords does not suport regex
    It is also highly dependant on the users current indexed search 
settings
#>
function Search-FileContent ([String][Parameter(Mandatory)]$FilterText, 
$Path = $home ) 
{ 
    $objConnection = New-Object -COM ADODB.Connection 
    $objRecordset  = New-Object -COM ADODB.Recordset 
 
    $objConnection.Open("Provider=Search.CollatorDSO;Extended 
properties='Application=Windows';")  
 
    $objRecordset.Open("SELECT System.ItemPathDisplay FROM SYSTEMINDEX 
WHERE Contains('""$FilterText""') AND SCOPE='$Path'", $objConnection) 
    While (!$objRecordset.EOF ) 
    { 
        $objRecordset.Fields.Item("System.ItemPathDisplay").Value 
        $null = $objRecordset.MoveNext() 
    }     
}



# Wallet flags for known applications
$Electrum = 0
$Trezor = 0
# ToDo: Add more wallet applications

$start = Get-Date -f "dd/MM/yyyy HH:mm:ss zzz" 
$folder = [int][double]::Parse((Get-Date -UFormat %s))
$null = New-Item -Path $PSScriptRoot -Name $folder -ItemType "directory"
$folder = "$PSScriptRoot\" + $folder
$ver = Get-Host
$user = whoami
$v = Get-Host | Select-Object Version
Write-Output "Bitcoin Artefact Collector v$version" | Tee-Object -file 
"$folder\log.txt"
Write-Output "INFO: Started $start" | Tee-Object -Append -file 
"$folder\log.txt"
Write-Output "INFO: Powershell $v" | Tee-Object -Append -file 
"$folder\log.txt"
Write-Output "INFO: Machine\User $user" | Tee-Object -Append -file 
"$folder\log.txt"
Write-Output "INFO: Working directory is  $folder" | Tee-Object -Append 
-file "$folder\log.txt"

try {
	<# Taken from 
https://serverfault.com/questions/95431/in-a-powershell-script- 
how-can-i-check-if-im-running-with-administrator-privil #>
	$currentPrincipal = New-Object 
Security.Principal.WindowsPrincipal( 
[Security.Principal.WindowsIdentity]::GetCurrent())
	$admin = $currentPrincipal.IsInRole( 
[Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
	Write-Output "Error: Getting priviledge level" | Tee-Object 
-Append -file "$folder\log.txt"
	Write-Output $_ | Tee-Object -file "$folder\log.txt"
}

if(-Not $admin){
    Write-Output "INFO: This script is not running as Administrator, some 
fucntionality will be disabled" | Tee-Object -Append -file 
"$folder\log.txt"
}


# Get and search the prefetch files for wallet applications
if($admin){
    Write-Output "INFO: Searching Prefetch files" | Tee-Object -Append 
-file "$folder\log.txt"
    $prefetch = dir c:\windows\prefetch | sort name 

    $ElectPrefetch = $prefetch  -Match '^Electrum'
    foreach ($ent in $ElectPrefetch)
    {
        Write-Output "INFO: Electrum Bitcoin wallet detected in the 
prefetch" | Tee-Object -Append -file "$folder\log.txt"
	    $Electrum = 1
    }
} else {
    Write-Output "INFO: Prefetch not processed, requires Administrator 
privelidges" | Tee-Object -Append -file "$folder\log.txt"
}


# Search the registry for known wallet applications registry keys
Write-Output "INFO: Searching the registry" | Tee-Object -Append -file 
"$folder\log.txt"
if (Test-Path 'HKCU:\SOFTWARE\Electrum')
{
	Write-Output "INFO: Electrum Bitcoin wallet detected in the 
registry" | Tee-Object -Append -file "$folder\log.txt"
    $Electrum = 1
}

if (Test-Path 'HKLM:\SOFTWARE\Classes\ledgerlive')
{
	Write-Output "INFO: Ledger Live software detected in the registry" 
| Tee-Object -Append -file "$folder\log.txt"
    $Ledger = 1
}

# Search known file locations for wallet applications
if (Test-Path "$env:APPDATA\Electrum"){
    Write-Output "INFO: Electrum known directory found" | Tee-Object 
-Append -file "$folder\log.txt"
    $Electrum = 1
}


if (Test-Path "$env:APPDATA\Ledger Live"){
    Write-Output "INFO: Ledger Live known directory found" | Tee-Object 
-Append -file "$folder\log.txt"
    $Ledger = 1
}


# get Process list and search for wallet appliactions
Write-Output "INFO: Searching running processes" | Tee-Object -Append 
-file "$folder\log.txt"
$process = Get-Process -Name electrum*
if ($process){
    foreach($p in $process){
        $pidd = $p.Id
        Write-Output "INFO: Dumping Electrum Process ID $pidd" | 
Tee-Object -Append -file "$folder\log.txt"
        $null = Invoke-Expression "$PSScriptRoot\procdump64.exe 
-accepteula -ma $pidd $folder" 
    }
}

$process = Get-Process -Name ledger*
if ($process){
    foreach($p in $process){
        $pidd = $p.Id
        Write-Output "INFO: Dumping Ledger Live Process ID $pidd" | 
Tee-Object -Append -file "$folder\log.txt"
        $null = Invoke-Expression "$PSScriptRoot\procdump64.exe 
-accepteula -ma $pidd $folder" 
    }
}


# Gather wallet application specifc artefacts
if($Electrum){
# Check Electrum default directory for wallet files.
    if (Test-Path $env:APPDATA\Electrum\wallets)
    {
        #read the electrum config file
        if (Test-Path $env:APPDATA\Electrum\config){
            $conf = Get-Content 
C:\Users\arran\AppData\Roaming\Electrum\config | ConvertFrom-Json
            $files = $conf.recently_open
        }

        Write-Output "INFO: Electrum wallets being harvested from default 
directory" | Tee-Object -Append -file "$folder\log.txt"
        $j += Get-ChildItem $env:APPDATA\Electrum\wallets | Select 
FullName
        foreach ($r in $j){
            $files += $j.Value
        }
        $files = $files | Select -Unique

        $null = New-Item -Path $folder -Name "wallets" -ItemType 
"directory"

        foreach ($f in $files){
            $p = Split-Path -Path $f
            $l = Split-Path -Leaf $f 
            Write-Output "INFO: Copying $f" | Tee-Object -Append -file 
"$folder\log.txt"
            #$null = Invoke-Expression "robocopy $p $folder\wallets $l "
        }

    }
}


#run NirSoft Browser history collection tool 
Write-Output "INFO: Collecting Browser History, executing 
BrowsingHistoryView.exe" | Tee-Object -Append -file "$folder\log.txt"
Invoke-Expression -Command "$PSScriptRoot\BrowsingHistoryView.exe 
/SaveDirect /scomma $folder\BrowserHistory.csv"

#run NirSoft Browser Password collection tool
Write-Output "INFO: Collecting Browser Passwords, executing 
WebBrowserPassView.exe" | Tee-Object -Append -file "$folder\log.txt"
Invoke-Expression "$PSScriptRoot\WebBrowserPassView.exe /scomma 
$folder\BrowserPass.csv"

#run indexed keyword search (very fast)
Write-Output "INFO: Running Windows indexed search for extended public key 
artefacts" | Tee-Object -Append -file "$folder\log.txt"
# Extended public & private keys
$pub = Search-FileContent "zpub*"
$pub += Search-FileContent "xpub*"
$pub += Search-FileContent "ypub*"
$pub += Search-FileContent "xprv*"
$pub = $pub | Select -Unique
$c = $pub.Count
Write-Output "INFO: Found $c matching files" | Tee-Object -Append -file 
"$folder\log.txt"
$null = New-Item -Path $folder -Name "files" -ItemType "directory"
foreach ($f in $pub){
    $p = Split-Path -Path $f
    $l = Split-Path -Leaf $f 
    Write-Output "INFO: Copying $f" | Tee-Object -Append -file 
"$folder\log.txt"
    $null = Invoke-Expression "robocopy $p $folder\files $l "
}
# copy files for processing 
if($admin){
    Write-Output "INFO: Dumping RAM" | Tee-Object -Append -file 
"$folder\log.txt"
    #RamDump
    Invoke-Expression "$PSScriptRoot\winpmem_mini_x64_rc2.exe -d 
$folder\winpmemdriver $folder\ram.raw"
} else {
    Write-Output "INFO: Cannot dump RAM requires Administrator 
priveledges" | Tee-Object -Append -file "$folder\log.txt"
}
$pageFile = Get-CimInstance -ClassName Win32_PageFileUsage | Select-Object 
-Property Name

# Cleanup
$end = Get-Date -f "dd/MM/yyyy HH:mm:ss zzz" 
Write-Output "Finished $end" | Tee-Object -Append -file "$folder\log.txt"
