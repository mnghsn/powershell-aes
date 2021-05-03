# PowerShell AES Encryption Script Set

A PowerShell script set to encrypt and decrypt file using AES algorithm.

## Features

- Encrypts a file using AES encryption.
- Decrypts a file using AES decryption.
- Generates an AES encryption key, IV and salt.
- Compatible with openssl-enc.

## Requirements

- PowerShell 5.0 or PowerShell Core
- .NET Framework or .NET Core

## Installation

The scripts are standalone and can run regardless of where the file is located on your machine.

## Usage

- Encrypt and decrypt a specified file.

  ```powershell
  # Encrypt "foobar.txt" to "foobar.txt.enc".
  Protect-AesFile -InFile foobar.txt -OutFile foobar.txt.enc -Password <password>

  # Decrypt "foobar.txt.enc" to "foobar.txt.dec"
  Unprotect-AesFile -InFile foobar.txt.enc -OutFile foobar.txt.dec -Password <password>
  ```

- Encrypt and decrypt a specified file as Base64 encoded string.

  ```powershell
  # Encrypt "foobar.txt" to "foobar.txt.enc".
  Protect-AesFile -InFile foobar.txt -OutFile foobar.txt.enc -Password <password> -AsBase64

  # Decrypt "foobar.txt.enc" to "foobar.txt.dec"
  Unprotect-AesFile -InFile foobar.txt.enc -OutFile foobar.txt.dec -Password <password> -AsBase64
  ```

- The file encrypted by this script can be decrypted by OpenSSL, and vice versa.

  ```powershell
  # Encrypt "foobar.txt" to "foobar.txt.enc".
  Protect-AesFile -InFile foobar.txt -OutFile foobar.txt.enc -Password <password>

  # Decrypt "foobar.txt.enc" to "foobar.txt.dec" using OpenSSL.
  openssl enc -aes256 -d -pbkdf2 -k <password> -in foobar.txt.enc -out foobar.txt.dec
  ```

  ```powershell
  # Encrypt "foobar.txt" to "foobar.txt.enc" using OpenSSL.
  openssl enc -aes256 -pbkdf2 -k <password> -in foobar.txt -out foobar.txt.enc

  # Decrypt "foobar.txt.enc" to "foobar.txt.dec".
  Unprotect-AesFile -InFile foobar.txt.enc -OutFile foobar.txt.dec -Password <password>
  ```

- Get detailed information about the scripts.

  ```powershell
  Get-Help -Detailed Protect-AesFile.ps1
  Get-Help -Detailed Unprotect-AesFile.ps1
  Get-Help -Detailed New-AesKey.ps1
  ```

## Disclaimer

The code within this repository comes with no guarantee. Use at your own risk.

## License

Licensed under the [MIT License](LICENSE.md).
