rule Suspicious_PDF
{
    meta:
        description = "Detects PDFs containing active or auto-executing content (possible malicious)"
        author = "security-bot"
        severity = "medium"
        category = "pdf"
        reference = "https://helpx.adobe.com/acrobat/kb/acrobat-javascript-security.html"

    strings:
        $js = "/JavaScript"
        $aa = "/AA"
        $open_action = "/OpenAction"
        $launch = "/Launch"
        $uri = "/URI"
        $rich_media = "/RichMedia"

    condition:
        filesize < 10MB and
        (
            2 of ($js, $aa, $open_action, $launch, $uri, $rich_media)
        )
}
