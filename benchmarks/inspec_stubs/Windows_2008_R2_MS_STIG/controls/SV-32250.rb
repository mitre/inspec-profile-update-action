control 'SV-32250' do
  title 'Outdated or unused accounts must be removed from the system or disabled.'
  desc 'Outdated or unused accounts provide penetration points that may go undetected.  Inactive accounts must be deleted if no longer necessary or, if still required, disabled until needed.'
  desc 'check', %q(Run "PowerShell".

Member servers and standalone systems:
Copy or enter the lines below to the PowerShell window and enter.  (Entering twice may be required. Do not include the quotes at the beginning and end of the query.)

"([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
 $user = ([ADSI]$_.Path)
 $lastLogin = $user.Properties.LastLogin.Value
 $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
 if ($lastLogin -eq $null) {
 $lastLogin = 'Never'
 }
 Write-Host $user.Name $lastLogin $enabled 
}"

This will return a list of local accounts with the account name, last logon, and if the account is enabled (True/False).
For example: User1 10/31/2015 5:49:56 AM True

Domain Controllers:
If the Active Directory PowerShell module has not been previously imported, enter the following first:
"Import-Module ActiveDirectory"
Enter the following command in PowerShell.
"Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00"

This will return accounts that have not been logged on to for 35 days, along with various attributes such as the Enabled status and LastLogonDate.

Review the list of accounts returned by the above queries to determine the finding validity for each account reported.

Exclude the following accounts:
Built-in administrator account (Renamed, SID ending in 500)
Built-in guest account (Renamed, Disabled, SID ending in 501)
Application accounts

If any enabled accounts have not been logged on to within the past 35 days, this is a finding.

Inactive accounts that have been reviewed and deemed to be required must be documented with the ISSO.)
  desc 'fix', 'Regularly review accounts to determine if they are still active. Disable or delete any active accounts that have not been used in the last 35 days.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-69269r2_chk'
  tag severity: 'low'
  tag gid: 'V-1112'
  tag rid: 'SV-32250r4_rule'
  tag gtitle: 'Dormant Accounts'
  tag fix_id: 'F-65713r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
