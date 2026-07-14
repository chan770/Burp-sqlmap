# Build the Standalone sqlmap Burp extension without Gradle, using javac + jar.
# Produces dist/burp-sqlmap.jar (compiled classes + Montoya service descriptor).
# Nothing is bundled — the user configures their own Python + sqlmap paths.
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

$classes = Join-Path $root "build/classes"
$dist    = Join-Path $root "dist"
New-Item -ItemType Directory -Force -Path $classes | Out-Null
New-Item -ItemType Directory -Force -Path $dist    | Out-Null

Write-Host "[build] Compiling extension..."
$srcFiles = Get-ChildItem -Recurse -Filter *.java (Join-Path $root "src/main/java") | ForEach-Object { $_.FullName }
& javac --release 17 -cp (Join-Path $root "lib/montoya-api.jar") -d $classes $srcFiles
if ($LASTEXITCODE -ne 0) { throw "javac failed" }

Write-Host "[build] Assembling jar..."
Copy-Item -Recurse -Force (Join-Path $root "src/main/resources/META-INF") $classes
$jar = Join-Path $dist "burp-sqlmap.jar"
& jar --create --file $jar -C $classes .
if ($LASTEXITCODE -ne 0) { throw "jar failed" }

Write-Host "[build] Built $jar"
Get-Item $jar | Select-Object Name, @{n='KB';e={[math]::Round($_.Length/1KB,1)}}
