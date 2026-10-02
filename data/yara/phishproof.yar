rule PhishProof_EICAR_Test
{
  meta:
    description = "Safe integration test for the PhishProof YARA path"
  strings:
    $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
  condition:
    $eicar
}

rule Suspicious_Office_Dropper_Strings
{
  meta:
    description = "Static Office dropper indicators; triage signal, not attribution"
  strings:
    $auto = "AutoOpen" nocase
    $shell = "WScript.Shell" nocase
    $download = "URLDownloadToFile" nocase
    $powershell = "powershell" nocase
  condition:
    2 of them
}
