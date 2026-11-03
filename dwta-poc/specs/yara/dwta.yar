// DwTA YARA-X rules (spec §5.5.3). meta.severity drives R-W4; meta.weight drives S-YARA.

rule EICAR_Test_File {
  meta:
    description = "EICAR antivirus test string"
    severity = "medium"
    weight = 10
  strings:
    $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
  condition:
    $eicar at 0
}

rule LNK_Points_To_Executable {
  meta:
    description = "Windows shortcut that launches an executable or script host"
    severity = "high"
    weight = 30
  strings:
    $exe = ".exe" ascii wide nocase
    $ps = "powershell" ascii wide nocase
    $cmd = "cmd.exe" ascii wide nocase
  condition:
    uint32(0) == 0x0000004C and any of them
}

rule Script_Download_Execute {
  meta:
    description = "Script that downloads and executes content"
    severity = "high"
    weight = 30
  strings:
    $a = "DownloadString" ascii wide nocase
    $b = "Invoke-WebRequest" ascii wide nocase
    $c = "IEX(" ascii wide nocase
    $d = "WScript.Shell" ascii wide nocase
  condition:
    any of them
}

rule PE_Inside_Document_Container {
  meta:
    description = "OOXML/ZIP container that carries an embedded Windows executable"
    severity = "high"
    weight = 30
  strings:
    $mz = { 4D 5A 90 00 }
  condition:
    uint32(0) == 0x04034B50 and $mz
}
