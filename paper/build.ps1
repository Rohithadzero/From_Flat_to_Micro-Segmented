# build.ps1 -- regenerate everything data-driven, then compile locally or package for Overleaf.
#
#   powershell -ExecutionPolicy Bypass -File paper\build.ps1
#
# Steps (each script reads ..\results, ..\configs, ..\research; writes only inside paper\):
#   1. fix_snapshot.py  pre-fix vs post-fix analyser snapshot   -> data\fix-impact.csv
#   2. make_figures.py  result figures (stamped EXPECTED until measured) -> figures\
#   3. gen_tables.py    every table + numbers.tex macros         -> tables\
#   4. merge_refs.py    merge ..\research\papers\refs.bib        -> refs.bib
#   5. check_tex.py     static LaTeX/bibliography check (fails the build on errors)
#   6. latexmk/pdflatex if on PATH, otherwise overleaf.zip
#   7. build_docx       paper.docx (python -> JSON -> node 'docx'), if node is available

$ErrorActionPreference = 'Stop'
$Paper = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root  = Split-Path -Parent $Paper
Set-Location $Paper

$py = $null
foreach ($c in @('python', 'py', 'python3')) {
    if (Get-Command $c -ErrorAction SilentlyContinue) { $py = $c; break }
}
if (-not $py) { throw 'Python not found on PATH' }

function Run-Py([string]$script, [string[]]$extra = @()) {
    & $py -I (Join-Path $Paper $script) @extra
    if ($LASTEXITCODE -ne 0) { throw "$script failed (exit $LASTEXITCODE)" }
}

# topology is a drawing, not data: copy it from the report figures
$topo = Join-Path $Root 'report\figures\topology.png'
New-Item -ItemType Directory -Force (Join-Path $Paper 'figures') | Out-Null
if (Test-Path $topo) { Copy-Item $topo (Join-Path $Paper 'figures\topology.png') -Force }

Run-Py 'fix_snapshot.py'
Run-Py 'make_figures.py'
Run-Py 'gen_tables.py'
Run-Py 'merge_refs.py'
Run-Py 'check_tex.py'

$latexmk  = Get-Command latexmk  -ErrorAction SilentlyContinue
$pdflatex = Get-Command pdflatex -ErrorAction SilentlyContinue
if ($latexmk) {
    & latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
    if ($LASTEXITCODE -ne 0) { throw 'latexmk failed; see main.log' }
    Write-Host 'Built main.pdf with latexmk'
} elseif ($pdflatex) {
    & pdflatex -interaction=nonstopmode -halt-on-error main.tex
    if (Get-Command bibtex -ErrorAction SilentlyContinue) { & bibtex main }
    & pdflatex -interaction=nonstopmode -halt-on-error main.tex
    & pdflatex -interaction=nonstopmode -halt-on-error main.tex
    if ($LASTEXITCODE -ne 0) { throw 'pdflatex failed; see main.log' }
    Write-Host 'Built main.pdf with pdflatex'
} else {
    Write-Host 'No LaTeX on PATH: packaging overleaf.zip'
    $Zip = Join-Path $Paper 'overleaf.zip'
    if (Test-Path $Zip) { Remove-Item $Zip -Force }
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $files = @()
    foreach ($i in @('main.tex', 'refs.bib', 'IEEEtran.cls', 'IEEEtran.bst')) { $files += Get-Item (Join-Path $Paper $i) }
    foreach ($d in @('sections', 'tables', 'figures')) { $files += Get-ChildItem (Join-Path $Paper $d) -File -Recurse }
    $archive = [System.IO.Compression.ZipFile]::Open($Zip, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($f in $files) {
            # forward slashes: Overleaf (Linux) treats '\' as part of the file name
            $rel = $f.FullName.Substring($Paper.Length + 1) -replace '\\', '/'
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $archive, $f.FullName, $rel, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
        }
    } finally { $archive.Dispose() }
    Write-Host ("Wrote {0} ({1} files)" -f $Zip, $files.Count)
}

# ---- Word version ----
if ((Get-Command node -ErrorAction SilentlyContinue) -and (Test-Path (Join-Path $Paper 'node_modules\docx'))) {
    Run-Py 'tex2json.py'
    & node (Join-Path $Paper 'build_docx.js')
    if ($LASTEXITCODE -ne 0) { throw 'build_docx.js failed' }
} else {
    Write-Warning 'node or node_modules\docx missing (run: npm install docx@9.5.1 --ignore-scripts in paper\); paper.docx not rebuilt'
}
