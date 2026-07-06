/*
SENTINEL AI Malware Signatures
YARA rules for malware detection
*/

rule suspicious_pe_imports {
    meta:
        description = "PE file with suspicious Windows API imports"
        author = "SentinelAI"
        severity = "high"
    strings:
        $kernel32_1 = "CreateRemoteThread" ascii wide
        $kernel32_2 = "VirtualAlloc" ascii wide
        $kernel32_3 = "WriteProcessMemory" ascii wide
        $kernel32_4 = "CreateProcess" ascii wide
        $advapi32_1 = "RegCreateKey" ascii wide
        $advapi32_2 = "RegSetValue" ascii wide
        $ws2_32_1 = "WSAStartup" ascii wide
        $ws2_32_2 = "connect" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($kernel32_*) or 1 of ($advapi32_*) or 2 of ($ws2_*))
}

rule packed_executable {
    meta:
        description = "Potentially packed executable with high entropy sections"
        author = "SentinelAI"
        severity = "medium"
    strings:
        $upx = "UPX!" ascii
        $pecompact = "PEC2" ascii
        $mew = "MEW" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of them or filesize > 100KB)
}

rule shellcode_patterns {
    meta:
        description = "Common shellcode patterns"
        author = "SentinelAI"
        severity = "critical"
    strings:
        $nop_sled = { 90 90 90 90 90 90 90 90 }
        $xor_decoder = { 31 C0 EB 05 5B 31 C9 31 D2 }
        $push_ret = { 68 ?? ?? ?? ?? C3 }
        $call_pop = { E8 00 00 00 00 58 }
    condition:
        any of them
}

rule ransomware_indicators {
    meta:
        description = "Ransomware behavioral indicators"
        author = "SentinelAI"
        severity = "critical"
    strings:
        $encrypt_ext = ".encrypted" ascii wide
        $ransom_note = "README.txt" ascii wide
        $bitcoin = "bitcoin" ascii nocase wide
        $decryptor = "decrypt" ascii nocase wide
        $vssadmin = "vssadmin delete shadows" ascii wide
        $cipher = "AES" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (3 of them)
}

rule keylogger_imports {
    meta:
        description = "Keylogger related imports"
        author = "SentinelAI"
        severity = "high"
    strings:
        $user32_1 = "GetAsyncKeyState" ascii wide
        $user32_2 = "GetKeyState" ascii wide
        $user32_3 = "SetWindowsHookEx" ascii wide
        $kernel32_1 = "MapVirtualKey" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (2 of them)
}

rule rootkit_indicators {
    meta:
        description = "Rootkit behavioral patterns"
        author = "SentinelAI"
        severity = "critical"
    strings:
        $dkom = "DKOM" ascii wide
        $ssdt_hook = "KeServiceDescriptorTable" ascii wide
        $idt_hook = "IDT" ascii wide
        $hide_process = "PsSetCreateProcessNotifyRoutine" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (any of them)
}

rule trojan_dropper {
    meta:
        description = "Trojan dropper with embedded executable"
        author = "SentinelAI"
        severity = "high"
    strings:
        $mz_embed = { 4D 5A [0-1000] 4D 5A }
        $dropper_1 = "DropFile" ascii wide
        $dropper_2 = "ShellExecute" ascii wide
        $temp_path = "%TEMP%" ascii wide
        $app_data = "%APPDATA%" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        ($mz_embed or (2 of ($dropper_*) and 1 of ($temp_path, $app_data)))
}

rule backdoor_rat {
    meta:
        description = "Remote Access Trojan (RAT) indicators"
        author = "SentinelAI"
        severity = "critical"
    strings:
        $rat_1 = "RemoteDesktop" ascii wide
        $rat_2 = "Keylogger" ascii wide
        $rat_3 = "Screenshot" ascii wide
        $c2_server = "C2Server" ascii wide
        $persistence = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (3 of them)
}

rule cryptominer {
    meta:
        description = "Cryptocurrency mining malware"
        author = "SentinelAI"
        severity = "high"
    strings:
        $miner_1 = "stratum+tcp://" ascii
        $miner_2 = "xmrig" ascii nocase
        $miner_3 = "nicehash" ascii nocase
        $cpu_miner = "cpuminer" ascii nocase
        $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/  // Bitcoin address pattern
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($miner_*) or $wallet)
}

rule banking_trojan {
    meta:
        description = "Banking trojan indicators"
        author = "SentinelAI"
        severity = "critical"
    strings:
        $bank_1 = "webinject" ascii nocase
        $bank_2 = "formgrabber" ascii nocase
        $bank_3 = "banking" ascii nocase
        $browser_hook = "browser_hook" ascii
        $ssl_strip = "sslstrip" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (2 of them)
}

rule worm_replication {
    meta:
        description = "Worm replication patterns"
        author = "SentinelAI"
        severity = "critical"
    strings:
        $worm_1 = "net view" ascii wide
        $worm_2 = "copy \\\\" ascii wide
        $worm_3 = "psexec" ascii nocase
        $worm_4 = "wmic" ascii nocase
        $share_enum = "\\\\*\\ADMIN$" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (2 of them)
}

rule spyware_keylogger {
    meta:
        description = "Spyware and keylogger malware"
        author = "SentinelAI"
        severity = "high"
    strings:
        $spy_1 = "GetWindowText" ascii wide
        $spy_2 = "GetClipboardData" ascii wide
        $spy_3 = "smtp" ascii nocase
        $spy_4 = "email" ascii nocase
        $ftp_upload = "ftp://" ascii
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($spy_*) or $ftp_upload)
}

rule adware_pua {
    meta:
        description = "Adware and Potentially Unwanted Applications"
        author = "SentinelAI"
        severity = "medium"
    strings:
        $ad_1 = "advertisement" ascii nocase
        $ad_2 = "popup" ascii nocase
        $ad_3 = "toolbar" ascii nocase
        $ad_4 = "browser extension" ascii nocase
        $registry_mod = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($ad_*) or $registry_mod)
}

rule exploit_kit {
    meta:
        description = "Exploit kit indicators"
        author = "SentinelAI"
        severity = "critical"
    strings:
        $exploit_1 = "JavaScript heap spray" ascii
        $exploit_2 = "ROP chain" ascii
        $exploit_3 = "DEP bypass" ascii
        $exploit_4 = "ASLR bypass" ascii
        $flash_exploit = "Flash Player" ascii wide
        $java_exploit = "Java Applet" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($exploit_*) or 1 of ($flash_exploit, $java_exploit))
}

rule file_infector {
    meta:
        description = "File infecting virus patterns"
        author = "SentinelAI"
        severity = "critical"
    strings:
        $infect_1 = "FindFirstFile" ascii wide
        $infect_2 = "FindNextFile" ascii wide
        $infect_3 = "CreateFile" ascii wide
        $infect_4 = "WriteFile" ascii wide
        $extension_filter = "*.exe" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (3 of ($infect_*) and $extension_filter)
}

rule bootkit_indicators {
    meta:
        description = "Bootkit malware indicators"
        author = "SentinelAI"
        severity = "critical"
    strings:
        $bootkit_1 = "MBR" ascii wide
        $bootkit_2 = "VBR" ascii wide
        $bootkit_3 = "BIOS" ascii wide
        $bootkit_4 = "\\Device\\Harddisk0\\Partition0" ascii wide
        $raw_disk = "\\\\.\\PhysicalDrive0" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($bootkit_*) or $raw_disk)
}

rule macro_malware {
    meta:
        description = "Office macro malware"
        author = "SentinelAI"
        severity = "high"
    strings:
        $macro_1 = "AutoOpen" ascii wide
        $macro_2 = "Document_Open" ascii wide
        $macro_3 = "Workbook_Open" ascii wide
        $vba_code = "VBA" ascii wide
