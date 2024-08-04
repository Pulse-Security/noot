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
	[Alias("o")]
	[Parameter(Mandatory = $true)]
	[String]$outfilename,

	[Alias("i")]
	[String]$ip = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { (($_.IPEnabled -ne $null) -and ($_.DefaultIPGateway -ne $null)) } | Select-Object IPAddress -First 1).IPAddress[0],

	[Alias("r")]
	[Switch]$resume,

	[Alias("s")]
	[Switch]$skipFileChecks,

	[Alias("x")]
	[String]$xferId = $null,

	[Alias("k")]
	[ValidatePattern('^[0-9A-Fa-f]{32}$')]
	[String]$key = $null
)

function Write-Log {
    param (
        [string]$Message
    )
    Write-Output "$(get-date -Format "u"): $Message"
}

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

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-Not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "Script must be run as admin"
    exit
}

$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

# parse or generate xferid, this is used to ignore other ICMP packets not relating to the transfer
$bxferId=[byte[]]::new(2)
if ($xferId) {
	$bxferId[0] = [Convert]::ToByte($xferId.Substring(0, 2), 16)
	$bxferId[1] = [Convert]::ToByte($xferId.Substring(2, 2), 16)
}
else {
	$rng.GetBytes($bxferId)
	$xferId = ([System.BitConverter]::ToString($bxferId)) -replace '-',''
	Write-Log "XferId not supplied, generating one (use this with the sender): $xferId"
}

# generate key if not provided
if (-Not $key) {
	$randomBytes = new-object byte[] 16
	$rng.GetBytes($randomBytes)
	$key = ($randomBytes|ForEach-Object ToString X2) -join ''
	Write-Log "No key specified, using generated one: $key"
}

# setup file streams
if ($resume) {
	Write-Log "Attempting to resume incomplete transfer..."

	$prevFileStream = New-Object -TypeName System.IO.FileStream -ArgumentList $outfilename,Open,ReadWrite
	Copy-Item -Force $outfilename ($outfilename + ".tempfile")
	$tempfilestream = New-Object -TypeName System.IO.FileStream -ArgumentList ($outfilename + ".tempfile"),Open,ReadWrite
} else {
	if (Test-Path -Path $outfilename) {
		Write-Log "$outfilename already exists. Exiting"
		exit 1
	}
	$tempfilestream = New-Object -TypeName System.IO.FileStream -ArgumentList ($outfilename + ".tempfile"),Create,ReadWrite
}

Write-Log "Data will be written to $outfilename"

$address = New-Object system.net.IPEndPoint([system.net.IPAddress]::Parse($ip), 0)

$ICMPSocket = New-Object System.Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw, [Net.Sockets.ProtocolType]::Icmp)
$ICMPSocket.bind($address)
$ICMPSocket.IOControl([Net.Sockets.IOControlCode]::ReceiveAll, [BitConverter]::GetBytes(1), $null) | Out-Null
$icmpRecvBuffer = new-object byte[] $ICMPSocket.ReceiveBufferSize
$xferStatus = $false
$pTotalChunks = 0

function SaveAndClose {
	$oldMissingChunks = new-object bool[] $pTotalChunks
	try {
		if ((-Not $dec.length -eq 0) -And $pChunkId -eq $pTotalChunks) {
			$finalLength = (($pTotalChunks * $bufSize) - $bufSize) + $dec.length
			$tempfilestream.SetLength($finalLength)
		}
	}
	catch {
		Write-Log "Something went wrong setting the final length, output file may end up with trailing data."
	}

	if ($skipFileChecks) {
		Write-Log "Instructed to skip post-transfer check for missing chunks in $outfilename.tempfile you're on your own"
	}
	else {
		Write-Log "Checking for missing chunks..."
		[byte[]]$emptyChunk = 0x4D, 0x49, 0x53, 0x53 # writing MISS into file where we've missed a chunk
		[byte[]]$nullByte = 0x00

		if ($resume) {
			[int]$chunkId = 0
			$missingFound = $false
			while ($prevFileStream.Read($chunk, 0, $bufSize)) {
				$chunkId += 1
				
				$oldMissingChunks[$chunkId-1] = $true
				if(([System.BitConverter]::ToString($chunk[0..3])) -eq ([System.BitConverter]::ToString($emptyChunk)) -And ([System.BitConverter]::ToString($chunk[($bufSize.Length - 1)..($emptyChunk.Length - 1)])) -eq ([System.BitConverter]::ToString($emptyChunk))) {
					$oldMissingChunks[$chunkId-1] = $false
					$missingFound = $true
				}
			}
			if (-Not $missingFound) {
				Write-Log "Resume attempted but no missing chunks found in existing file, try re-running with -s"
				$skipFileChecks = $true
			}
		}

		if (!$skipFileChecks) {
			$missingChunks = [System.Collections.Generic.List[int]]::new()
			[array]::copy($emptyChunk,0,$chunk,0,$emptyChunk.length)
			for (($i2 = ($emptyChunk.length)); $i2 -lt (($bufSize - $emptyChunk.length - 1)); $i2++) {
				[array]::copy($nullByte,0,$chunk,$i2,1)
			}
			[array]::copy($emptyChunk,0,$chunk,($bufSize - $emptyChunk.length),$emptyChunk.length)
			for (($i=0); $i -le ($pTotalChunks-1); $i++) {
				if ($chunkTracker[$i] -eq $false -And $oldMissingChunks[$i] -eq $false) { # didnt receive chunk this time or previously 
					$null = $tempfilestream.Seek($i * $bufSize,0)
					$tempfilestream.Write($chunk, 0, $chunk.length)
					$missingChunks.Add(($i+1))
				}
			}
		}
	}

	if (!$skipFileChecks) {
		if ($missingChunks.length -gt 0) {
			$sb = [System.Text.StringBuilder]::new() # make the resumechunks string
			[int]$lt | Out-Null
			$sb.Append("(") | Out-Null
			for (($i=0); $i -lt $missingChunks.count; $i++) {
				$lt = $missingChunks[$i]
				$sb.Append($missingChunks[$i]) | Out-Null
				while($i -lt ($missingChunks.count -1) -And $missingChunks[$i+1] -eq ($missingChunks[$i]+1)) {
					$i++
				}
				if($lt -ne $missingChunks[$i]) {
					$sb.Append("..").Append($missingChunks[$i]) | Out-Null
				}
				if($i -ne ($missingChunks.count -1)) {
					if($i -eq 0) {
						$sb.Append("..").Append($missingChunks[$i]) | Out-Null
					}
					$sb.Append("+") | Out-Null
				}
				else {
					$sb.Append(")") | Out-Null
				}
			}
			Write-Log "Chunks are missing, rerun the listener by adding a -r. E.g:"
			Write-Log " .\listen.ps1 -o $outfilename -x $xferId -k $key -r"
			Write-Log "Resume sender by adding -r <missingpackets> and rerunning it. E.g:"
			Write-Log " .\sender.ps1 -i <infile> -h <desthost> -c $bufSize -x $xferId -r $sb"
		}
		else {
			Write-Log "No missing chunks found."
		}
	}

	if ($resume -eq $true) {
		$prevFileStream.Close()
	}

	$tempfilestream.Close()
	Move-Item -Force ($outfilename + ".tempfile") $outfilename
	Write-Log "Exiting"
}

$exiting = $false
$chunkLastSeen = "None"
Write-Log "Ready to receive data, listening on $ip"

$keyBytes = ConvertHexStringToByteArray($key)

while (-Not $exiting) {
	if([System.BitConverter]::ToString($icmpRecvBuffer[20]) -eq "08") { # check its an echo request (type 8)
		$pXferId = $icmpRecvBuffer[28..29]
		[int]$bufSize = [System.BitConverter]::ToInt32($icmpRecvBuffer[30..33],0)
		$pChunkId = [System.BitConverter]::ToInt32(($icmpRecvBuffer[34..37]),0)
		$pTotalChunks = [System.BitConverter]::ToInt32(($icmpRecvBuffer[38..41]),0)
		$pPayloadLen = [System.BitConverter]::ToInt16(($icmpRecvBuffer[42..43]),0)
		[byte[]] $pPayload = $icmpRecvBuffer[44..($pPayloadLen+43)]

		if((([System.BitConverter]::ToString($pXferId)) -replace '-','') -eq $xferId) { # incoming transfer id matches 
			$chunkLastSeen = "$pChunkId"
			if ($null -eq $chunkTracker -or $chunkTracker[$pChunkId-1] -ne $true) {

				if ($xferStatus -eq $false) {
					$chunk = [byte[]]::new($bufSize)
					if (-Not $resume) {
						$tempfilestream.SetLength($pTotalChunks * $bufSize)
					}
					$chunkTracker = new-object bool[] $pTotalChunks
					$xferStatus = $true
					Write-Log "Receiving data: $pTotalChunks chunks * $bufSize byte chunksize"
				}

				$tempfileOffset = ($pChunkId-1) * $bufSize
				$tempfilestream.Seek($tempfileOffset,0) | Out-Null
				$outstream = New-Object IO.MemoryStream
				$ms = New-Object System.IO.MemoryStream -ArgumentList (,$pPayload)

				$iv = New-Object Byte[](16)
				$ms.Read($iv, 0, $iv.Length) | Out-Null

				$aes = New-Object Security.Cryptography.AesManaged
				$decryptor = $aes.CreateDecryptor($keyBytes, $iv)

				$cryptostream = New-Object System.Security.Cryptography.CryptoStream( $ms, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)

				try {
					$cryptostream.CopyTo($outstream)
					if ($chunkLastSeen % 10 -eq 0) { 
						Write-Log "Writing chunk $chunkLastSeen"
					}
					$dec = $outstream.ToArray()
					$tempfilestream.Write($dec, 0, $dec.length)

					$chunkTracker[$pChunkId-1] = $true
					if (($xferStatus -eq $true) -And ($pChunkId -eq $pTotalChunks)) {
						Write-Log "Received final chunk"
						SaveAndClose
						break
					}
				}
				catch {
					Write-Log "Chunk $chunkLastSeen decryption failed. Check your key or try reducing the chunksize."
				}
			}
		}
	}

	# receive icmp
	$icmpRecvBuffer[0] = 0x00 # ensure this is 0x00 as we're checking it in the spin-wait loop
	$socketAsyncEventArgs = new-object System.Net.Sockets.SocketAsyncEventArgs
	$socketAsyncEventArgs.SetBuffer($icmpRecvBuffer, 0, $ICMPSocket.ReceiveBufferSize)
	$socketAsyncEventArgs.RemoteEndPoint = $Address

	$ICMPSocket.ReceiveFromAsync($socketAsyncEventArgs) | Out-Null

	# spinning to wait on icmp packet showing up... this is fine...
	while ($icmpRecvBuffer[0] -eq 0x00 -And !$exiting) {
		Start-Sleep -Milliseconds 1

		# handle ctrl + c pressed during wait
		while ($host.UI.RawUI.KeyAvailable -and ($k = $host.UI.RawUI.ReadKey("AllowCtrlC,NoEcho,IncludeKeyUp"))) {
			Write-Log "XferId: $xferId, last seen chunk: $chunkLastSeen, using key: $key"
			if ([Int]$k.Character -eq 3) {
				Write-Log "Ctrl+c pressed, exiting"
				$exiting = $true
			}
			$host.UI.RawUI.FlushInputBuffer()
		}
	}
}

# handle exiting
if ($exiting) {
	if ($xferStatus) {
		Write-Log "Transfer $xferId interrupted, cleaning up..."
		SaveAndClose
	}
	else {
		$tempfilestream.Close()
		Remove-Item ($outfilename + ".tempfile" )
	
		if ($resume) {
			$prevFileStream.Close()
		}
	}
}