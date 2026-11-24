# naa-check

Checks the ConfigMgr Network Access Account (NAA) configured on a machine and
reports what Active Directory knows about that account (group membership,
adminCount, delegation flags).

## Usage

```powershell
# Default: read the NAA account name if stored in clear text, check its AD
# rights. Sealed policy secrets are left untouched.
.\Get-NaaDomainCheck.ps1

# Opt-in decryption: unseal the policy secret, run the same checks against
# the decrypted account. Password is verified but not printed.
.\Get-NaaDomainCheck.ps1 -Decrypt

# Also print the recovered password. Only use with a trusted output
# destination.
.\Get-NaaDomainCheck.ps1 -Decrypt -ShowPassword
```

Run elevated (or as a ConfigMgr script, which runs as SYSTEM) — reading the
CCM policy store and unsealing DPAPI-protected secrets both require that
context.

## Decryption behaviour

- Nothing is decrypted unless `-Decrypt` is passed explicitly.
- A sealed username value is unsealed via DPAPI
  (`ProtectedData::Unprotect`, `LocalMachine` scope) and then goes through
  the normal account/rights checks.
- The password is only read from the policy when `-Decrypt` is set, and is
  only printed when `-ShowPassword` is also set.
- If unsealing fails (wrong context, corrupted secret), the value counts as
  still sealed and the script says so — no exception text is echoed, so
  secret material cannot leak through error messages.
