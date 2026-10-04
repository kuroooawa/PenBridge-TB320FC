# 生成 Hook 重签名用的自签密钥，并导出 v2 签名所需的材料。
#
#   pwsh tools/gen_key.ps1 [-Password penbridge] [-Alias penbridge] [-JdkDir "C:\Program Files\Zulu\zulu-23\bin"]
#
# 产物（build/keys/，已 gitignore）：
#   penbridge-tb320fc.p12  PKCS#12 密钥库（含自签证书）
#   cert.der               X.509 证书 DER
#   spki.der               SubjectPublicKeyInfo DER
#   params.txt             modulus / privateExponent / publicExponent / bits
#
# 注意：这是本构建专用的自签密钥，不是可信密钥；换成自己的密钥后，设备上必须先卸载
# 旧签名的 Hook（com.aclaniakea.lenovopenbridge）再安装新包。

param(
    [string]$Password = "penbridge",
    [string]$Alias = "penbridge",
    [string]$CommonName = "PenBridge TB320FC",
    [string]$JdkDir = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$keys = Join-Path $root "build\keys"
New-Item -ItemType Directory -Force -Path $keys | Out-Null

function Find-Tool([string]$name) {
    if ($JdkDir -and (Test-Path (Join-Path $JdkDir "$name.exe"))) { return (Join-Path $JdkDir "$name.exe") }
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw "$name not found; pass -JdkDir <jdk bin dir>"
}

$keytool = Find-Tool "keytool"
$java = Find-Tool "java"
$store = Join-Path $keys "penbridge-tb320fc.p12"
if (Test-Path $store) { Remove-Item $store -Force }

& $keytool -genkeypair -keystore $store -storetype PKCS12 -alias $Alias `
    -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -validity 10950 `
    -storepass $Password -keypass $Password `
    -dname "CN=$CommonName, OU=PenBridge, O=PenBridge, C=CN"

& $java (Join-Path $root "tools\KeyExport.java") $store $Password $Alias `
    (Join-Path $keys "cert.der") (Join-Path $keys "spki.der") (Join-Path $keys "params.txt")

Write-Host ""
Write-Host "keystore : $store"
Write-Host "password : $Password"
Write-Host "next     : python tools/patch_hook.py"
