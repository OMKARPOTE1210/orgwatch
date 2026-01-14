rule EICAR_Test_File {
    meta:
        description = "Standard Anti-Virus Test File"
        severity = "Critical"
    strings:
        $s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $s1
}

rule Suspicious_Powershell {
    meta:
        description = "Encoded PowerShell commands"
        severity = "High"
    strings:
        $s1 = "FromBase64String" nocase
        $s2 = "Hidden" nocase
        $s3 = "Bypass" nocase
        $s4 = "Net.WebClient" nocase
    condition:
        $s1 and ($s2 or $s3 or $s4)
}

rule Ransomware_Note {
    meta:
        description = "Common Ransomware Notes"
        severity = "Critical"
    strings:
        $s1 = "encrypted" nocase
        $s2 = "bitcoin" nocase
        $s3 = "DECRYPT_FILES" nocase
        $s4 = "restore your files" nocase
    condition:
        any of them
}

rule AD_Attack_Tools {
    meta:
        description = "Mimikatz and Recon tools signatures"
        severity = "Critical"
    strings:
        $m1 = "sekurlsa::logonpasswords" nocase
        $m2 = "lsadump::sam" nocase
        $m3 = "privilege::debug" nocase
    condition:
        any of them
}

rule Reverse_Shells {
    meta:
        description = "Common reverse shell patterns"
        severity = "Critical"
    strings:
        $nc = "nc -e"
        $bash = "/bin/bash -i"
        $cmd = "cmd.exe /c"
        $sock = "socket.socket"
    condition:
        any of them
}

rule Keylogger_Hooks {
    meta:
        description = "Windows API calls used for keylogging"
        severity = "High"
    strings:
        $k1 = "SetWindowsHookEx"
        $k2 = "GetAsyncKeyState"
        $k3 = "GetForegroundWindow"
    condition:
        all of them
}