<#
.SYNOPSIS
    Checks the Network Access Account this computer already has.

.DESCRIPTION
    Reads CCM_NetworkAccessAccount on this computer and, when the account name
    is stored in clear text, checks whether that account is a domain account
    and which rights Active Directory records for it.

    Rights come from a normal LDAP lookup as the computer's current domain
    session: group membership, adminCount, and delegation flags.

    Sealed policy secrets are never decrypted by default. Only when the
    operator explicitly passes -Decrypt does the script unseal the
    NetworkAccessUsername value (and, with -ShowPassword, the
    NetworkAccessPassword value) so the same checks can run against a sealed
    policy. Decryption requires SYSTEM context (run elevated) because the
    policy secrets are protected with DPAPI for the local machine.

.EXAMPLE
    .\Get-NaaDomainCheck.ps1
    Checks the NAA account without touching sealed policy secrets.

.EXAMPLE
    .\Get-NaaDomainCheck.ps1 -Decrypt
    Unseals the NAA policy secret because it was explicitly requested, then
    runs the normal account and rights checks. The recovered password is
    reported as recovered but not displayed.

.EXAMPLE
    .\Get-NaaDomainCheck.ps1 -Decrypt -ShowPassword
    Same as -Decrypt, but the recovered password is also printed. Use only
    when the output destination is trusted.

.NOTES
    Run elevated, or deploy it as a Configuration Manager script. Those run
    as SYSTEM, which can read the policy and query the domain.

    Without -Decrypt this script does not decrypt policy secrets, does not
    read NetworkAccessPassword, and does not sign in as the Network Access
    Account.
#>
[CmdletBinding()]
param(
    # Explicit opt-in: unseal the NAA policy secret before checking the
    # account. Nothing is decrypted unless the caller passes this switch.
    [switch] $Decrypt,

    # Only effective together with -Decrypt. Prints the recovered password;
    # by default the password is verified but not displayed.
    [switch] $ShowPassword
)

function Test-SealedSecret {
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($Value -match '(?i)PolicySecret|CDATA|\bDPAPI\b') { return $true }
    $compact = ($Value -replace '\s', '')
    if ($compact.Length -ge 40 -and $compact -match '^[0-9A-Fa-f]+$') { return $true }
    if ($Value.Length -ge 80 -and $Value -notmatch '[\\@]') { return $true }
    return $false
}

function Get-AccountSam {
    param([string] $Name)
    if ($Name -match '^[^\\]+\\(.+)$') { return $Matches[1] }
    if ($Name -match '^([^@]+)@.+$') { return $Matches[1] }
    if ($Name -match '^\.[\\/](.+)$') { return $Matches[1] }
    return $Name
}

function Get-AccountKindName {
    param([string] $Name, [string] $Computer)
    if ([string]::IsNullOrWhiteSpace($Name)) { return 'empty' }
    $lower = $Name.ToLowerInvariant()
    foreach ($scope in @('nt authority\', 'builtin\', 'window manager\', 'font driver host\', 'nt service\')) {
        if ($lower.StartsWith($scope)) { return 'builtin' }
    }
    if ($lower.StartsWith('.\') -or $lower.StartsWith('./')) { return 'local' }
    if ($Name -match '^([^\\]+)\\([^\\]+)$') {
        if ($Matches[1] -eq $Computer) { return 'local' }
        return 'downlevel'
    }
    if ($Name -match '^[^@\\]+@[^@\\]+$') { return 'upn' }
    return 'unqualified'
}

function ConvertTo-LdapFilterValue {
    param([string] $Value)
    if ($null -eq $Value) { return '' }
    $escaped = $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29')
    return $escaped.Replace([string][char]0, '\00')
}

function Get-MachineSidValue {
    try {
        $user = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID } | Select-Object -First 1
        if ($user -and $user.SID.AccountDomainSid) { return [string] $user.SID.AccountDomainSid.Value }
    } catch { }
    try {
        $account = Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' |
            Where-Object { $_.SID } | Select-Object -First 1
        if ($account.SID) {
            $parts = ([string] $account.SID).Split('-')
            if ($parts.Length -ge 4) { return ($parts[0..($parts.Length - 2)] -join '-') }
        }
    } catch { }
    return $null
}

function Test-LocalSam {
    param([string] $Sam)
    if ([string]::IsNullOrWhiteSpace($Sam)) { return $false }
    try { return [bool](Get-LocalUser -Name $Sam -ErrorAction Stop) } catch { }
    try {
        $escaped = $Sam.Replace("'", "''")
        return [bool](Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True AND Name='$escaped'")
    } catch { return $false }
}

function Resolve-AccountSid {
    param([string] $Name)
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($Name)).Translate(
            [System.Security.Principal.SecurityIdentifier])
        $domainSid = $null
        if ($sid.AccountDomainSid) { $domainSid = [string] $sid.AccountDomainSid.Value }
        return [pscustomobject]@{
            Resolved = $true
            Sid      = [string] $sid.Value
            DomainSid = $domainSid
            Error    = $null
        }
    } catch {
        $message = [string] $_.Exception.Message
        if ($message.Length -ge 300 -or (Test-SealedSecret $message)) {
            $message = 'The account name could not be translated to a SID.'
        }
        return [pscustomobject]@{ Resolved = $false; Sid = $null; DomainSid = $null; Error = $message }
    }
}

function Get-PropertyValue {
    param($Result, [string] $Name)
    $values = $Result.Properties[$Name]
    if ($null -eq $values -or $values.Count -eq 0) { return $null }
    return $values[0]
}

function Get-DirectoryRights {
    param([string] $Name)
    $info = [ordered]@{
        Found        = $false
        Reachable    = $false
        DistinguishedName = $null
        Groups       = @()
        Privileged   = @()
        Flags        = @()
        Error        = $null
    }
    try {
        Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
        $root = [ADSI]'LDAP://RootDSE'
        $naming = [string] $root.defaultNamingContext
        if ([string]::IsNullOrWhiteSpace($naming)) { throw 'No default naming context.' }
        $info.Reachable = $true
        $sam = Get-AccountSam -Name $Name
        $filter = '(&(objectClass=user)(sAMAccountName=' + (ConvertTo-LdapFilterValue $sam) + '))'
        if ($Name -match '^[^@\\]+@[^@\\]+$') {
            $filter = '(&(objectClass=user)(|(sAMAccountName=' + (ConvertTo-LdapFilterValue $sam) +
                ')(userPrincipalName=' + (ConvertTo-LdapFilterValue $Name) + ')))'
        }
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]('LDAP://' + $naming)
        $searcher.Filter = $filter
        $searcher.PageSize = 1
        foreach ($property in @('distinguishedName', 'sAMAccountName', 'userAccountControl', 'adminCount', 'memberOf')) {
            [void]$searcher.PropertiesToLoad.Add($property)
        }
        $found = $searcher.FindOne()
        if (-not $found) { return [pscustomobject]$info }
        $info.Found = $true
        $dn = [string](Get-PropertyValue $found 'distinguishedName')
        $info.DistinguishedName = $dn
        $groups = New-Object System.Collections.Generic.List[string]
        foreach ($member in @($found.Properties['memberOf'])) {
            $text = [string] $member
            if ($text -match '^CN=([^,]+)') { $groups.Add($Matches[1]) }
        }
        $info.Groups = @($groups)

        $uac = 0
        $uacValue = Get-PropertyValue $found 'userAccountControl'
        if ($null -ne $uacValue) { $uac = [int] $uacValue }
        $flags = New-Object System.Collections.Generic.List[string]
        if ($uac -band 2) { $flags.Add('disabled') }
        if ($uac -band 65536) { $flags.Add('password never expires') }
        if ($uac -band 32) { $flags.Add('password not required') }
        if ($uac -band 524288) { $flags.Add('unconstrained delegation') }
        if ($uac -band 16777216) { $flags.Add('constrained delegation') }
        $adminCount = Get-PropertyValue $found 'adminCount'
        if ($null -ne $adminCount -and [int] $adminCount -eq 1) { $flags.Add('adminCount') }
        $info.Flags = @($flags)

        if (-not [string]::IsNullOrWhiteSpace($dn)) {
            $entry = [ADSI]('LDAP://' + $dn)
            $entry.RefreshCache(@('tokenGroups'))
            $privileged = New-Object System.Collections.Generic.List[string]
            foreach ($groupSid in @($entry.tokenGroups)) {
                $sid = New-Object System.Security.Principal.SecurityIdentifier($groupSid, 0)
                $value = [string] $sid.Value
                if ($value -match '-512$') { $privileged.Add('Domain Admins') }
                elseif ($value -match '-519$') { $privileged.Add('Enterprise Admins') }
                elseif ($value -match '-518$') { $privileged.Add('Schema Admins') }
                elseif ($value -eq 'S-1-5-32-544') { $privileged.Add('Administrators') }
                elseif ($value -match '-544$' -and $value.StartsWith('S-1-5-21-')) { $privileged.Add('Builtin Administrators') }
                elseif ($value -match '-548$') { $privileged.Add('Account Operators') }
            }
            $info.Privileged = @($privileged | Select-Object -Unique)
        }
    } catch {
        $message = [string] $_.Exception.Message
        if ($message.Length -ge 300 -or (Test-SealedSecret $message)) {
            $message = 'The directory lookup did not complete.'
        }
        $info.Error = $message
    }
    return [pscustomobject]$info
}

function ConvertFrom-PolicySecret {
    <#
    .SYNOPSIS
        Unseals a ConfigMgr policy secret, only when decryption was requested.

    .DESCRIPTION
        A sealed policy value looks like:
            <PolicySecret Version="1"><![CDATA[<hex DPAPI blob>]]></PolicySecret>
        The DPAPI blob is unprotected for the local machine (which is why this
        needs SYSTEM/elevated context) and returned as a plain string. Any
        failure returns $null; errors are swallowed so secret material can
        never leak through exception messages.
    #>
    param([string] $Secret)
    if ([string]::IsNullOrWhiteSpace($Secret)) { return $null }

    $text = $Secret.Trim()
    if ($text -match '(?s)<!\[CDATA\[(.+?)\]\]>') { $text = $Matches[1].Trim() }
    elseif ($text -match '(?s)>.*<\s*/\s*PolicySecret') {
        # Fallback: value nested directly inside the PolicySecret element.
        $text = ($text -replace '(?s)^.*?>', '' -replace '(?s)<\s*/\s*PolicySecret.*?$', '').Trim()
    }

    $bytes = $null
    $compact = ($text -replace '\s', '')
    if ($compact.Length -gt 0 -and $compact.Length % 2 -eq 0 -and $compact -match '^[0-9A-Fa-f]+$') {
        $bytes = New-Object byte[] ($compact.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $bytes[$i] = [Convert]::ToByte($compact.Substring($i * 2, 2), 16)
        }
    } else {
        try { $bytes = [Convert]::FromBase64String($text) } catch { return $null }
    }

    try {
        Add-Type -AssemblyName System.Security -ErrorAction Stop
        $plain = [Security.Cryptography.ProtectedData]::Unprotect(
            $bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
        $value = [Text.Encoding]::Unicode.GetString($plain)
        $value = $value.TrimEnd([char]0).Trim()
        if ($value.Length -eq 0) { return $null }
        return $value
    } catch {
        return $null
    }
}

function Write-AccountReport {
    param(
        [string] $Computer,
        [string] $Account,
        [string] $MachineSid,
        [bool] $PartOfDomain,
        [string] $RecoveredPassword
    )
    $kindName = Get-AccountKindName -Name $Account -Computer $Computer
    $sam = Get-AccountSam -Name $Account
    $local = Test-LocalSam -Sam $sam
    $resolved = Resolve-AccountSid -Name $Account
    $sidIsMachine = [bool]($resolved.DomainSid -and $MachineSid -and $resolved.DomainSid -eq $MachineSid)
    $wellKnown = $false
    if ($resolved.Sid) {
        $sidText = $resolved.Sid.ToUpperInvariant()
        $wellKnown = $sidText -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20') -or $sidText.StartsWith('S-1-5-32-')
    }

    $directory = $null
    if ($kindName -in @('downlevel', 'upn', 'unqualified') -and $PartOfDomain) {
        $directory = Get-DirectoryRights -Name $Account
    }

    $foreignSid = [bool]($resolved.DomainSid -and $MachineSid -and $resolved.DomainSid -ne $MachineSid -and -not $wellKnown)
    $kind = 'unqualified'
    if ($kindName -eq 'builtin' -or $wellKnown) { $kind = 'builtin' }
    elseif ($kindName -eq 'local' -or $sidIsMachine) { $kind = 'local' }
    elseif ($kindName -eq 'unqualified') { $kind = 'unqualified' }
    elseif (($directory -and $directory.Found) -or $foreignSid) { $kind = 'domain' }
    elseif ($kindName -in @('downlevel', 'upn')) { $kind = 'unresolved' }

    Write-Output ('Account: ' + $Account)
    Write-Output ('Kind: ' + $kind)
    if ($resolved.Sid) { Write-Output ('SID: ' + $resolved.Sid) }
    if ($local -and $kind -eq 'domain') {
        Write-Output 'Note: this computer also has a local user with the same SAM name.'
    }
    if ($kind -eq 'unqualified' -and $directory -and $directory.Found) {
        Write-Output 'Note: a domain user has this SAM name, but the policy value has no domain prefix.'
    }
    if ($sam.EndsWith('$')) {
        Write-Output 'Note: this is a computer account.'
    }
    if ($directory) {
        if ($directory.Error) { Write-Output ('Directory: ' + $directory.Error) }
        elseif (-not $directory.Found) { Write-Output 'Directory: no matching domain user.' }
        else {
            $rights = New-Object System.Collections.Generic.List[string]
            foreach ($item in @($directory.Privileged)) { if ($item) { $rights.Add($item) } }
            foreach ($item in @($directory.Flags)) { if ($item) { $rights.Add($item) } }
            if ($rights.Count -eq 0) { Write-Output 'Rights: no privileged group, delegation flag, or adminCount.' }
            else { Write-Output ('Rights: ' + ($rights -join '; ')) }
            if ($directory.Groups.Count -gt 0) {
                Write-Output ('Groups: ' + ($directory.Groups -join '; '))
            }
        }
    } elseif (-not $PartOfDomain -and $kindName -in @('downlevel', 'upn')) {
        Write-Output 'Directory: this computer is not domain-joined, so rights were not queried.'
    }
    if ($resolved.Error -and -not $resolved.Resolved) { Write-Output ('Resolve: ' + $resolved.Error) }
    if ($PSBoundParameters.ContainsKey('RecoveredPassword')) {
        if ($null -eq $RecoveredPassword) {
            Write-Output 'Password: sealed and could not be unsealed (wrong context or corrupted secret).'
        } elseif ($ShowPassword) {
            Write-Output ('Password: ' + $RecoveredPassword)
        } else {
            Write-Output 'Password: recovered, not displayed (pass -ShowPassword to print it).'
        }
    }
    Write-Output ''
}

$computer = $env:COMPUTERNAME
$computerSystem = $null
try { $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop } catch { }
$partOfDomain = [bool]($computerSystem -and $computerSystem.PartOfDomain)
$machineSid = Get-MachineSidValue

$policyError = $null
$usernameValues = @()
$passwordValues = @()
try {
    $instances = @(Get-CimInstance -Namespace 'root\ccm\policy\Machine\ActualConfig' -ClassName 'CCM_NetworkAccessAccount' -ErrorAction Stop)
    foreach ($item in $instances) {
        $usernameValues += [string] $item.NetworkAccessUsername
        if ($Decrypt) { $passwordValues += [string] $item.NetworkAccessPassword }
    }
    $instances = $null
} catch {
    $message = [string] $_.Exception.Message
    if ($message -notmatch 'Invalid namespace|Invalid class|not found|not supported') {
        if ($message.Length -lt 300 -and -not (Test-SealedSecret $message)) { $policyError = $message }
        else { $policyError = 'Could not read the CCM policy store on this computer.' }
    }
}

$clearNames = New-Object System.Collections.Generic.List[string]
$clearPasswords = @{}
$sealedCount = 0
$decryptedCount = 0
$decryptFailedCount = 0
for ($i = 0; $i -lt $usernameValues.Count; $i++) {
    $value = $usernameValues[$i]
    if ([string]::IsNullOrWhiteSpace($value)) { continue }
    if (Test-SealedSecret $value) {
        if ($Decrypt) {
            # Decryption was explicitly requested by the caller.
            $plain = ConvertFrom-PolicySecret -Secret $value
            if ($null -ne $plain) {
                $decryptedCount += 1
                if (-not $clearNames.Contains($plain)) {
                    $clearNames.Add($plain)
                    if ($i -lt $passwordValues.Count) { $clearPasswords[$plain] = $passwordValues[$i] }
                }
                continue
            }
            $decryptFailedCount += 1
        }
        $sealedCount += 1
        continue
    }
    $trimmed = $value.Trim()
    if (-not $clearNames.Contains($trimmed)) {
        $clearNames.Add($trimmed)
        if ($Decrypt -and $i -lt $passwordValues.Count) { $clearPasswords[$trimmed] = $passwordValues[$i] }
    }
}

# With -Decrypt, also recover the passwords for the accounts we can report on.
$recoveredPasswords = @{}
if ($Decrypt) {
    foreach ($name in $clearNames) {
        if (-not $clearPasswords.ContainsKey($name)) { continue }
        $secret = $clearPasswords[$name]
        if ([string]::IsNullOrWhiteSpace($secret)) { $recoveredPasswords[$name] = ''; continue }
        if (Test-SealedSecret $secret) {
            $recoveredPasswords[$name] = ConvertFrom-PolicySecret -Secret $secret
        } else {
            $recoveredPasswords[$name] = $secret.Trim()
        }
    }
}

Write-Output ('Computer: ' + $computer)
Write-Output ('Domain joined: ' + $(if ($partOfDomain) { 'yes' } else { 'no' }))
Write-Output ('NAA policy instances: ' + @($usernameValues).Count)
if ($policyError) { Write-Output ('Policy: ' + $policyError) }
Write-Output ('Decryption: ' + $(if ($Decrypt) { 'requested by caller (-Decrypt)' } else { 'not requested; sealed secrets left untouched' }))

if ($clearNames.Count -eq 0 -and $sealedCount -eq 0) {
    Write-Output 'Account: none'
    Write-Output 'Kind: no NAA policy'
    return
}

if ($sealedCount -gt 0 -and $clearNames.Count -eq 0) {
    Write-Output 'Account: sealed'
    Write-Output 'Kind: not checked'
    if ($Decrypt) {
        Write-Output ('Note: ' + $sealedCount + ' policy secret(s) could not be unsealed. Decryption needs SYSTEM/elevated context on the machine that holds the policy.')
    } else {
        Write-Output 'Note: this computer has a Network Access Account policy, and the account name is sealed. Rights are not queried, because decryption was not requested.'
    }
    return
}

if ($sealedCount -gt 0) {
    Write-Output ('Note: ' + $sealedCount + ' additional policy secret(s) were left sealed.')
}
if ($decryptFailedCount -gt 0) {
    Write-Output ('Note: ' + $decryptFailedCount + ' sealed secret(s) failed to decrypt.')
}

foreach ($account in $clearNames) {
    $passwordArg = @{}
    if ($Decrypt) { $passwordArg['RecoveredPassword'] = $recoveredPasswords[$account] }
    Write-AccountReport -Computer $computer -Account $account -MachineSid $machineSid -PartOfDomain $partOfDomain @passwordArg
}
