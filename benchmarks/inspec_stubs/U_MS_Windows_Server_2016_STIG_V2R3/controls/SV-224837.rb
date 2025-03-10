control 'SV-224837' do
  title 'Outdated or unused accounts must be removed from the system or disabled.'
  desc 'Outdated or unused accounts provide penetration points that may go undetected. Inactive accounts must be deleted if no longer necessary or, if still required, disabled until needed.

'
  desc 'check', %q(Open "Windows PowerShell".

Domain Controllers:

Enter "Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00"

This will return accounts that have not been logged on to for 35 days, along with various attributes such as the Enabled status and LastLogonDate.

Member servers and standalone systems:

Copy or enter the lines below to the PowerShell window and enter. (Entering twice may be required. Do not include the quotes at the beginning and end of the query.)

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

Review the list of accounts returned by the above queries to determine the finding validity for each account reported.

Exclude the following accounts:

- Built-in administrator account (Renamed, SID ending in 500)
- Built-in guest account (Renamed, Disabled, SID ending in 501)
- Built-in default account (Renamed, Disabled, SID ending in 503)
- Application accounts

If any enabled accounts have not been logged on to within the past 35 days, this is a finding.

Inactive accounts that have been reviewed and deemed to be required must be documented with the ISSO.)
  desc 'fix', 'Regularly review accounts to determine if they are still active. Remove or disable accounts that have not been used in the last 35 days.'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26528r465413_chk'
  tag severity: 'medium'
  tag gid: 'V-224837'
  tag rid: 'SV-224837r569186_rule'
  tag stig_id: 'WN16-00-000210'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-26516r465414_fix'
  tag satisfies: ['SRG-OS-000104-GPOS-00051', 'SRG-OS-000118-GPOS-00060']
  tag 'documentable'
  tag legacy: ['V-73259', 'SV-87911']
  tag cci: ['CCI-000764', 'CCI-000795']
  tag nist: ['IA-2', 'IA-4 e']
end
