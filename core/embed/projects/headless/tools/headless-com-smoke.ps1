[CmdletBinding()]
param(
    [string]$Port,
    [switch]$RebootToBootloader,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-ReplyPrefix {
    param(
        [Parameter(Mandatory)] [string]$Reply,
        [Parameter(Mandatory)] [string]$ExpectedPrefix
    )

    if (-not $Reply.StartsWith($ExpectedPrefix, [System.StringComparison]::Ordinal)) {
        throw "Unexpected device reply '$Reply'; expected prefix '$ExpectedPrefix'"
    }
}

function Assert-ReplyExact {
    param(
        [Parameter(Mandatory)] [string]$Reply,
        [Parameter(Mandatory)] [string]$Expected
    )

    if (-not [string]::Equals($Reply, $Expected, [System.StringComparison]::Ordinal)) {
        throw "Unexpected device reply '$Reply'; expected '$Expected'"
    }
}

function Assert-ErrorReply {
    param([Parameter(Mandatory)] [string]$Reply)
    Assert-ReplyPrefix -Reply $Reply -ExpectedPrefix 'ERROR'
}

function Invoke-ResponseValidatorSelfTest {
    Assert-ReplyExact -Reply 'OK hello' -Expected 'OK hello'
    Assert-ErrorReply -Reply 'ERROR 10'

    $RejectedMalformedReply = $false
    try {
        Assert-ReplyPrefix -Reply 'MALFORMED' -ExpectedPrefix 'OK'
    }
    catch {
        $RejectedMalformedReply = $true
    }

    if (-not $RejectedMalformedReply) {
        throw 'Response validator accepted malformed output'
    }
}

function Invoke-DeviceCommand {
    param(
        [Parameter(Mandatory)] [System.IO.Ports.SerialPort]$Serial,
        [Parameter(Mandatory)] [string]$Command
    )

    $Serial.WriteLine($Command)
    $Reply = $Serial.ReadLine().TrimEnd([char]13, [char]10)
    Write-Verbose "$Command -> $Reply"
    return $Reply
}

try {
    Invoke-ResponseValidatorSelfTest

    if ($SelfTest) {
        Write-Output 'headless-com-smoke self-test: PASS'
        return
    }

    if ([string]::IsNullOrWhiteSpace($Port)) {
        throw 'Specify the application COM port with -Port COMx'
    }

    $AvailablePorts = [System.IO.Ports.SerialPort]::GetPortNames()
    if ($AvailablePorts -notcontains $Port) {
        throw "COM port '$Port' is not present. Available: $($AvailablePorts -join ', ')"
    }

    $Serial = [System.IO.Ports.SerialPort]::new(
        $Port,
        115200,
        [System.IO.Ports.Parity]::None,
        8,
        [System.IO.Ports.StopBits]::One
    )
    $Serial.Encoding = [System.Text.Encoding]::ASCII
    $Serial.Handshake = [System.IO.Ports.Handshake]::None
    $Serial.NewLine = "`n"
    $Serial.ReadTimeout = 3000
    $Serial.WriteTimeout = 3000
    $Serial.DtrEnable = $true

    try {
        $Serial.Open()
        $Serial.DiscardInBuffer()
        $Serial.DiscardOutBuffer()

        Assert-ReplyExact `
            -Reply (Invoke-DeviceCommand -Serial $Serial -Command 'ping hello') `
            -Expected 'OK hello'
        Assert-ReplyExact `
            -Reply (Invoke-DeviceCommand -Serial $Serial -Command 'version') `
            -Expected 'OK ts5-headless-dev 0.1.0 T3T1'
        Assert-ErrorReply `
            -Reply (Invoke-DeviceCommand -Serial $Serial -Command 'otp-write')

        $Payload64 = 'a' * 64
        $Valid128 = 'ping ' + $Payload64 + (' ' * 59)
        $Invalid129 = 'ping ' + $Payload64 + (' ' * 60)
        if ($Valid128.Length -ne 128 -or $Invalid129.Length -ne 129) {
            throw 'Internal smoke-test line construction error'
        }

        Assert-ReplyExact `
            -Reply (Invoke-DeviceCommand -Serial $Serial -Command $Valid128) `
            -Expected "OK $Payload64"
        Assert-ErrorReply `
            -Reply (Invoke-DeviceCommand -Serial $Serial -Command $Invalid129)
        Assert-ErrorReply `
            -Reply (Invoke-DeviceCommand -Serial $Serial -Command ('ping ' + ('b' * 65)))

        if ($RebootToBootloader) {
            Assert-ReplyExact `
                -Reply (Invoke-DeviceCommand -Serial $Serial -Command 'reboot-to-bootloader') `
                -Expected 'OK'
        }
    }
    finally {
        if ($Serial.IsOpen) {
            $Serial.Close()
        }
        $Serial.Dispose()
    }

    Write-Output 'headless COM smoke: PASS'
}
catch {
    Write-Error $_
    exit 1
}
