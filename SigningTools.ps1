function Update-FileSignature {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[ValidateNotNullorEmpty()]
		[string]$Path
	)
	$MySigner = (Get-ChildItem cert:\CurrentUser\My -codesign)[0]
	if ((Test-Path $Path) -and ($null -ne $MySigner.Thumbprint)) {
		Set-AuthenticodeSignature $Path @MySigner
	}
	else {
		Out-Host "$($Path) not found or signer cert missing"
	}
}
New-Alias -Name Sign-ScriptFile -Value Update-FileSignature
New-Alias -Name Update-ScriptFileSignature -Value Update-FileSignature

function Export-ScriptFunctions {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[ValidateNotNullorEmpty()]
		[string]$Path
	)
	Get-Content -Path $Path | Select-String "^function "|%{$_.tostring().replace('function ','').replace(' {','')}
}

function Export-ScriptAliases {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[ValidateNotNullorEmpty()]
		[string]
		$Path
	)
	Get-Content -Path $Path | Select-String "^Set-Alias "|%{$_.tostring().replace('Set-Alias -Name ','') -replace '\ -Value .{5,500}',''}
}

function Generate-MachineKey {
  [CmdletBinding()]
  param (
    [ValidateSet("AES", "DES", "3DES")]
    [string]$decryptionAlgorithm = 'AES',
    
	[ValidateSet("MD5", "SHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512")]
    [string]$validationAlgorithm = 'HMACSHA256'
  )
  process {
    function BinaryToHex {
        [CmdLetBinding()]
        param($bytes)
        process {
            $builder = new-object System.Text.StringBuilder
            foreach ($b in $bytes) {
              $builder = $builder.AppendFormat([System.Globalization.CultureInfo]::InvariantCulture, "{0:X2}", $b)
            }
            $builder
        }
    }
    switch ($decryptionAlgorithm) {
      "AES" { $decryptionObject = new-object System.Security.Cryptography.AesCryptoServiceProvider }
      "DES" { $decryptionObject = new-object System.Security.Cryptography.DESCryptoServiceProvider }
      "3DES" { $decryptionObject = new-object System.Security.Cryptography.TripleDESCryptoServiceProvider }
    }
    $decryptionObject.GenerateKey()
    $decryptionKey = BinaryToHex($decryptionObject.Key)
    $decryptionObject.Dispose()
    switch ($validationAlgorithm) {
      "MD5" { $validationObject = new-object System.Security.Cryptography.HMACMD5 }
      "SHA1" { $validationObject = new-object System.Security.Cryptography.HMACSHA1 }
      "HMACSHA256" { $validationObject = new-object System.Security.Cryptography.HMACSHA256 }
      "HMACSHA385" { $validationObject = new-object System.Security.Cryptography.HMACSHA384 }
      "HMACSHA512" { $validationObject = new-object System.Security.Cryptography.HMACSHA512 }
    }
    $validationKey = BinaryToHex($validationObject.Key)
    $validationObject.Dispose()
    [string]::Format([System.Globalization.CultureInfo]::InvariantCulture,
      "<machineKey decryption=`"{0}`" decryptionKey=`"{1}`" validation=`"{2}`" validationKey=`"{3}`" />",
      $decryptionAlgorithm.ToUpperInvariant(), $decryptionKey,
      $validationAlgorithm.ToUpperInvariant(), $validationKey)
  }
}
<#
function New-ScriptFunction {
	param(
		[Parameter(Mandatory)]
		[ValidateNotNullorEmpty()]
		[string]$Path
	)
	
}

function New-ScriptFunction {
	param(
		[Parameter(Mandatory)]
		[ValidateNotNullorEmpty()]
		[string]$Path
	)
	
}
#>