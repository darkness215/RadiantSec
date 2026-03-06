$ContentDir = Join-Path $PSScriptRoot "content"
$updated = 0

Get-ChildItem -Path $ContentDir -Recurse -Filter "*.md" | ForEach-Object {
    $content = [System.IO.File]::ReadAllText($_.FullName)
    $newContent = $content -replace ' \{linenos=table\}', ''
    if ($content -ne $newContent) {
        [System.IO.File]::WriteAllText($_.FullName, $newContent, [System.Text.UTF8Encoding]::new($false))
        $rel = $_.FullName.Substring($ContentDir.Length + 1)
        Write-Host "  Updated: $rel"
        $updated++
    }
}

Write-Host ""
Write-Host "$updated files updated."
