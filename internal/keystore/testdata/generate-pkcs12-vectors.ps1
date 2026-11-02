param([string]$OpenSSL='C:\Program Files\Git\usr\bin\openssl.exe')
$ErrorActionPreference='Stop'
$opensslVersion=& $OpenSSL version
if($LASTEXITCODE -ne 0) { throw 'Cannot run OpenSSL' }
# All inputs/passwords are deliberately public test values.
$cases=@(
    @{name='sha1'; digest='SHA1'; oid='1.3.14.3.2.26'; length=20; password='password'; iterations=1},
    @{name='sha224'; digest='SHA224'; oid='2.16.840.1.101.3.4.2.4'; length=28; password='password'; iterations=2048},
    @{name='sha256'; digest='SHA256'; oid='2.16.840.1.101.3.4.2.1'; length=32; password='password'; iterations=2048},
    @{name='sha384'; digest='SHA384'; oid='2.16.840.1.101.3.4.2.2'; length=48; password='password'; iterations=1000},
    @{name='sha512'; digest='SHA512'; oid='2.16.840.1.101.3.4.2.3'; length=64; password='password'; iterations=2048},
    @{name='empty'; digest='SHA256'; oid='2.16.840.1.101.3.4.2.1'; length=32; password=''; iterations=2048},
    @{name='bmp'; digest='SHA256'; oid='2.16.840.1.101.3.4.2.1'; length=32; password='Пароль'; iterations=2048},
    @{name='long-password'; digest='SHA256'; oid='2.16.840.1.101.3.4.2.1'; length=32; password=('p'*80); iterations=2048}
)
$message=[Text.Encoding]::ASCII.GetBytes('independent PKCS12 MAC test')
$messagePath=Join-Path ([IO.Path]::GetTempPath()) ('pkcs12-public-'+[Guid]::NewGuid().ToString('N')+'.bin')
[IO.File]::WriteAllBytes($messagePath,$message)
try {
    $vectors=foreach($case in $cases) {
        $encodedPassword=[Convert]::ToHexString([Text.Encoding]::BigEndianUnicode.GetBytes($case.password+[char]0)).ToLower()
        $salt='0102030405060708'
        $rawKey=& $OpenSSL kdf -keylen $case.length -kdfopt ('digest:'+$case.digest) -kdfopt ('hexpass:'+$encodedPassword) -kdfopt ('hexsalt:'+$salt) -kdfopt id:3 -kdfopt ('iter:'+$case.iterations) PKCS12KDF
        if($LASTEXITCODE -ne 0) { throw 'KDF failed' }
        $key=($rawKey -join '').Replace(':','').Trim().ToLower()
        $rawMac=& $OpenSSL mac -macopt ('digest:'+$case.digest) -macopt ('hexkey:'+$key) -in $messagePath HMAC
        if($LASTEXITCODE -ne 0) { throw 'MAC failed' }
        @{name=$case.name; oid=$case.oid; password=$case.password; saltHex=$salt; iterations=$case.iterations; keyHex=$key; messageHex=[Convert]::ToHexString($message).ToLower(); macHex=($rawMac -join '').Trim().ToLower()}
    }
    @{producer=$opensslVersion; vectors=@($vectors)} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'pkcs12-mac-openssl.json') -Encoding utf8NoBOM
} finally { Remove-Item -LiteralPath $messagePath }
