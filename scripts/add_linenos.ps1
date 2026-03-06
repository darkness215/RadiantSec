# add_linenos.ps1
# Adds {linenos=inline} to fenced code blocks with more than 10 lines
# across all markdown files under .\content\

$ContentDir = Join-Path $PSScriptRoot "content"
$MinLines   = 10
$totalFiles = 0
$totalPatch = 0

foreach ($file in Get-ChildItem -Path $ContentDir -Recurse -Filter "*.md") {
    $lines   = [System.IO.File]::ReadAllLines($file.FullName)
    $result  = [System.Collections.Generic.List[string]]::new()
    $patches = 0
    $i       = 0

    while ($i -lt $lines.Count) {
        $line = $lines[$i]

        # Match an opening code fence: ```lang  or ```lang {opts}
        if ($line -match '^(`{3,})([\w\-]*)(.*?)$') {
            $fence = $Matches[1]
            $lang  = $Matches[2]
            $opts  = $Matches[3]

            # Find closing fence
            $j    = $i + 1
            $body = [System.Collections.Generic.List[string]]::new()

            while ($j -lt $lines.Count) {
                if ($lines[$j] -match '^`{3,}\s*$') { break }
                $body.Add($lines[$j])
                $j++
            }

            if ($body.Count -gt $MinLines -and $opts -notmatch 'linenos') {
                if ($opts.Trim() -match '^\{.*\}$') {
                    $opts = $opts.TrimEnd('}') + ', linenos=inline}'
                } else {
                    $opts = $opts + ' {linenos=inline}'
                }
                $patches++
            }

            $result.Add($fence + $lang + $opts)
            foreach ($bl in $body) { $result.Add($bl) }
            if ($j -lt $lines.Count) {
                $result.Add($lines[$j])
                $i = $j + 1
            } else {
                $i = $j
            }
        } else {
            $result.Add($line)
            $i++
        }
    }

    if ($patches -gt 0) {
        [System.IO.File]::WriteAllLines($file.FullName, $result, [System.Text.UTF8Encoding]::new($false))
        $rel = $file.FullName.Substring($ContentDir.Length + 1)
        Write-Host ("  [{0,2} blocks]  {1}" -f $patches, $rel)
        $totalFiles++
        $totalPatch += $patches
    }
}

Write-Host "`n$totalPatch code blocks updated across $totalFiles files."
