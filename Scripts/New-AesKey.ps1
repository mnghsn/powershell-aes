#Requires -Version 5.0

<#
.SYNOPSIS
    Generates an AES encryption key, IV and salt.

.DESCRIPTION
    This PowerShell script generates an AES 128-, 192- or 256-bit key,
    initialization vector (IV) and salt.

.PARAMETER KeySize
    Specifies the bit size of the encryption key. The acceptable values for this
    parameter are `128`, `192` and `256`. The default value is `256`.

.PARAMETER Password
    Specifies the password to derive the encryption key from. This script uses
    PBKDF2 as key derivation function.

.PARAMETER PasswordFile
    Specifies the file from which this script reads the first line as the
    password to derive the encryption key from. Enter a path and file name. If
    the path is omitted, the default is the current location.

.PARAMETER Salt
    Specifies the actual salt to derive the encryption key from. Enter a string
    composed only of hex digits. If the parameter is omitted, this script
    randomly generates a new one.

.PARAMETER Iter
    Specifies the number of iterations on the password in deriving the
    encryption key. The default value is `10000`.

.PARAMETER OutFile
    Specifies the output file for which this script saves the result. Enter a
    path and file name. If the path is omitted, the default is the current
    location. By default, this script returns the result to the pipeline.

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
    [Parameter()]
    [ValidateSet(128, 192, 256)]
    [Int32]
    $KeySize = 256,

    [Parameter(ParameterSetName = 'Password')]
    [String]
    $Password,

    [Parameter(ParameterSetName = 'PasswordFile')]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [String]
    $PasswordFile,

    [Parameter()]
    [ValidatePattern('^[0-9A-F]+$')]
    [String]
    $Salt,

    [Parameter()]
    [Int32]
    $Iter = 10000,

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

# Make sure that the .NET Framework sees the same working directory as
# PowerShell.
[System.IO.Directory]::SetCurrentDirectory($PWD)

# Get the salt as a byte array.
if ($Salt) {
    $saltBytes = $Salt | Format-HexString -Bytes 8 | ConvertFrom-HexString
} else {
    $saltBytes = New-Object Byte[] 8
    $prng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $prng.GetBytes($saltBytes)
}

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

# Create the result object.
$result = [Ordered]@{
    Salt = ($saltBytes | ConvertTo-HexString)
    Key = ($keyBytes | ConvertTo-HexString)
    Iv = ($ivBytes | ConvertTo-HexString)
}

# Output the result.
if ($OutFile) {
    $OutFile = [System.IO.Path]::GetFullPath($OutFile)
    if ($PSCmdlet.ShouldProcess($OutFile)) {
        $lines = $result.Keys | ForEach-Object { '{0,-3}={1}' -f $_.ToLower(), $result[$_] }
        [System.IO.File]::WriteAllLines($OutFile, $lines)
    }
}

# Return the result to the pipeline.
if ((-not $OutFile) -or ($OutFile -and $PassThru)) {
    $result
}
