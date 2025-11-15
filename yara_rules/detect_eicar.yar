rule EICAR_Test_File
{
    meta:
        description = "Detects the EICAR antivirus test file (safe test signature)"
        author = "security-bot"
        reference = "https://www.eicar.org/"
        severity = "low"
        category = "test"
        safe = "true"

    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    condition:
        $eicar
}
