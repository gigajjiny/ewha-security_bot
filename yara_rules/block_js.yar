rule Suspicious_JS
{
    meta:
        description = "Flags potentially malicious or obfuscated JavaScript files"
        author = "security-bot"
        severity = "medium"
        category = "javascript"

    strings:
        $eval = "eval("
        $unescape = "unescape("
        $document_write = "document.write("
        $fromCharCode = "String.fromCharCode("
        $atob = "atob("
        $xor = /[a-zA-Z0-9]{10,}\s*\^\s*[0-9]{2,}/  // XOR-based obfuscation pattern

    condition:
        filesize < 500KB and
        (
            2 of ($eval, $unescape, $document_write, $fromCharCode, $atob) or
            $xor
        )
}
