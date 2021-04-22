#Requires -Version 5.0

<#
.SYNOPSIS
    Encrypts a file using AES encryption.

.DESCRIPTION
    This PowerShell script encrypts the specified file using AES encryption.

.PARAMETER KeySize
    Specifies the bit size of the encryption key. The acceptable values for this
    parameter are `128`, `192` and `256`. The default value is `256`.

.PARAMETER CipherMode
    Specifies the block cipher mode to use for encryption. The acceptable values
    for this parameter are `CBC` or `ECB`. The default value is `CBC`.

.PARAMETER InFile
    Specifies the input file path to be encrypted.

.PARAMETER Password
    Specifies the password to derive the encryption key from. This script uses
    PBKDF2 as key derivation function.

.PARAMETER PasswordFile
    Specifies the file from which this script reads the first line as the
    password to derive the encryption key from. Enter a path and file name. If
    the path is omitted, the default is the current location.

.PARAMETER KeyString
    Specifies the actual key to use. Enter a string composed only of hex digits.
    If the parameter is omitted, the key is generated from the password and
    salt.

.PARAMETER IvString
    Specifies the actual initialization vector (IV) to use. Enter a string
    composed only of hex digits. If the parameter is omitted, the IV is
    generated from the password and salt.

.PARAMETER Salt
    Specifies the actual salt to derive the encryption key from. Enter a string
    composed only of hex digits. If the parameter is omitted, this script
    randomly generates a new one.

.PARAMETER Iter
    Specifies the number of iterations on the password in deriving the
    encryption key. The default value is `10000`.

.PARAMETER AsBase64
    Indicates the output file should be written as a Base64 encoded string.

.PARAMETER OutFile
    Specifies the output file path for which this script saves the encrypted
    data. Enter a path and file name. If the path is omitted, the default is the
    current location. By default, this script returns the result to the
    pipeline.

.PARAMETER PassThru
    Indicates that this script returns the result, in addition to writing them
    to a file. This parameter is valid only when the `-OutFile` parameter is
    also used in the command.
#>

################################################################################
# Parameters
################################################################################

[CmdletBinding(
    DefaultParameterSetName = 'Password',
    SupportsShouldProcess
)]

param (
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [Alias('FullName')]
    [String]
    $InFile,

    [Parameter()]
    [ValidateSet(128, 192, 256)]
    [Int32]
    $KeySize = 256,

    [Parameter()]
    [ValidateSet('CBC', 'ECB')]
    [String]
    $CipherMode = 'CBC',

    [Parameter(ParameterSetName = 'Password')]
    [String]
    $Password,

    [Parameter(ParameterSetName = 'PasswordFile')]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [String]
    $PasswordFile,

    [Parameter(ParameterSetName = 'Key', Mandatory)]
    [ValidatePattern('^[0-9A-F]+$')]
    [String]
    $KeyString,

    [Parameter(ParameterSetName = 'Key', Mandatory)]
    [ValidatePattern('^[0-9A-F]+$')]
    [String]
    $IvString,

    [Parameter()]
    [ValidatePattern('^[0-9A-F]+$')]
    [String]
    $Salt,

    [Parameter()]
    [Int32]
    $Iter = 10000,

    [Parameter()]
    [Switch]
    $AsBase64,

    [Parameter()]
    [ValidateScript({ Test-Path -LiteralPath $_ -IsValid })]
    [String]
    $OutFile,

    [Parameter()]
    [Switch]
    $PassThru
)

################################################################################
# Declarations
################################################################################

# Ensure that this script uses the strictest available version.
Set-StrictMode -Version Latest

# Exit this script when an error occurred.
$ErrorActionPreference = 'Stop'

################################################################################
# Functions
################################################################################

function ConvertFrom-HexString {
    [CmdletBinding()]
    [OutputType([Byte[]])]

    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidatePattern('^[0-9A-F]+$')]
        [String]
        $String
    )

    end {
        $Input = if ($Input) { $Input } else { $String }
        [Byte[]]($Input -replace '..', '0x$&,' -split ',' -ne '')
    }
}

function ConvertTo-HexString {
    [CmdletBinding()]
    [OutputType([String])]

    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [Byte[]]
        $Bytes
    )

    end {
        $Input = if ($Input) { $Input } else { $Bytes }
        ($Input | ForEach-Object { $_.ToString('X2') }) -join ''
    }
}

function Format-HexString {
    [CmdletBinding()]
    [OutputType([String])]

    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidatePattern('^[0-9A-F]+$')]
        [String]
        $String,

        [Parameter()]
        [Int32]
        $Bytes = 8
    )

    begin {
        $hexLength = $Bytes * 2
    }

    process {
        switch ($String) {
            { $_.Length -lt $hexLength } { $_.PadRight($hexLength, '0') }
            { $_.Length -gt $hexLength } { $_.Substring(0, $hexLength) }
            default { $_ }
        }
    }
}

################################################################################
# Execution
################################################################################

try {
    # Make sure that the .NET Framework sees the same working directory as
    # PowerShell.
    [System.IO.Directory]::SetCurrentDirectory($PWD)

    # Resolve the input file path.
    $InFile = [System.IO.Path]::GetFullPath($InFile)

    if ($PSCmdlet.ShouldProcess($InFile)) {
        # Create input and output streams.
        $inStream = New-Object System.IO.FileStream $InFile, Open, Read
        $outStream = New-Object System.IO.MemoryStream

        # Get the salt as a byte array.
        if ($Salt) {
            $saltBytes = $Salt | Format-HexString -Bytes 8 | ConvertFrom-HexString
        } else {
            $saltBytes = New-Object Byte[] 8
            $prng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
            $prng.GetBytes($saltBytes)
        }

        # Get the encryption key and IV as byte arrays.
        if ($KeyString -and $IvString) {
            $keyBytes = $KeyString | Format-HexString -Byte ($KeySize / 8) | ConvertFrom-HexString
            $ivBytes = $IvString | Format-HexString -Byte 16 | ConvertFrom-HexString
        } else {
            # Get the password to derive the encryption key from.
            if ($PasswordFile) {
                $PasswordFile = [System.IO.Path]::GetFullPath($PasswordFile)
                $Password = [System.IO.File]::ReadLines($PasswordFile)
            }
            # Use PBKDF2 to derive the encryption key and IV from the password and salt.
            try {
                # Use SHA256 as digest. (.NET Framework 4.7.2+)
                $pbkdf2 =
                    New-Object `
                        -TypeName System.Security.Cryptography.Rfc2898DeriveBytes `
                        -ArgumentList $Password, $saltBytes, $Iter, SHA256
            } catch [System.Management.Automation.MethodException] {
                # Use SHA1 as digest. (.NET Framework 4.7.1-)
                $pbkdf2 =
                    New-Object `
                        -TypeName System.Security.Cryptography.Rfc2898DeriveBytes `
                        -ArgumentList $Password, $saltBytes, $Iter
            }
            $keyBytes = $pbkdf2.GetBytes($KeySize / 8)
            $ivBytes = $pbkdf2.GetBytes(16)
        }

        # Print verbose messages.
        [PSCustomObject]@{
            Salt = ($saltBytes | ConvertTo-HexString)
            Key = ($keyBytes | ConvertTo-HexString)
            Iv = ($ivBytes | ConvertTo-HexString)
        } | Format-List | Out-String -Stream | Where-Object { $_ } | Write-Verbose

        # Add prefix to the salt to match OpenSSL format.
        $saltBytes = [System.Text.Encoding]::UTF8.GetBytes('Salted__') + $saltBytes

        # Create an AES instance.
        $aes = New-Object System.Security.Cryptography.AesManaged
        $aes.BlockSize = 128
        $aes.KeySize = $KeySize
        $aes.Mode = $CipherMode
        $aes.Padding = 'PKCS7'
        $aes.Key = $keyBytes
        $aes.Iv = $ivBytes

        # Create a crypto stream.
        $encryptor = $aes.CreateEncryptor()
        $cryptoStream =
            New-Object `
                -TypeName System.Security.Cryptography.CryptoStream `
                -ArgumentList $outStream, $encryptor, Write

        # Write the salt to the output stream.
        $outStream.Write($saltBytes, 0, $saltBytes.Length)

        # Write the encrypted data to the output stream.
        $inStream.CopyTo($cryptoStream)
        $cryptoStream.FlushFinalBlock()

        # Output the result.
        $outputBytes = $outStream.ToArray()
        $shouldPassThru = (-not $OutFile) -or ($OutFile -and $PassThru)
        if ($OutFile) { $OutFile = [System.IO.Path]::GetFullPath($OutFile) }
        if ($AsBase64) {
            $base64 = [System.Convert]::ToBase64String($outputBytes, 1)
            if ($OutFile) { [System.IO.File]::WriteAllText($OutFile, $base64) }
            if ($shouldPassThru) { $base64 }
        } else {
            if ($OutFile) { [System.IO.File]::WriteAllBytes($OutFile, $outputBytes) }
            if ($shouldPassThru) { [System.Text.Encoding]::UTF8.GetString($outputBytes) }
        }
    }
} finally {
    # Clean up.
    if (
        (Test-Path -Path Variable:cryptoStream) -and
        (Get-Member -InputObject $cryptoStream -Name 'Dispose' -MemberType Methods)
    ) {
        Write-Verbose 'Dispose crypto stream.'
        $cryptoStream.Dispose()
    }
    if (
        (Test-Path -Path Variable:inStream) -and
        (Get-Member -InputObject $inStream -Name 'Dispose' -MemberType Methods)
    ) {
        Write-Verbose 'Dispose input file stream.'
        $inStream.Dispose()
    }
    if (
        (Test-Path -Path Variable:outStream) -and
        (Get-Member -InputObject $outStream -Name 'Dispose' -MemberType Methods)
    ) {
        Write-Verbose 'Dispose output memory stream.'
        $outStream.Dispose()
    }
    if (
        (Test-Path -Path Variable:aes) -and
        (Get-Member -InputObject $aes -Name 'Dispose' -MemberType Methods)
    ) {
        Write-Verbose 'Dispose AES instance.'
        $aes.Dispose()
    }
}
