control 'SV-225439' do
  title 'Windows 2012 / 2012 R2 must automatically remove or disable temporary user accounts after 72 hours.'
  desc 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.

Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation.

If temporary accounts are used, the operating system must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.

To address access requirements, many operating systems may be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Determine if temporary user accounts are used and identify any that exist. If none exist, this is NA.

Review temporary user accounts for expiration dates.

Open "PowerShell".

Domain Controllers:

Enter "Search-ADAccount -AccountExpiring -TimeSpan 3:00:00:00 | FT Name, AccountExpirationDate"
This will return any accounts configured to expire within the next 3 days.  (The "TimeSpan" value to can be changed to find accounts configured to expire at various times such as 30 for the next month.)

If any accounts identified as temporary are not listed, this is a finding.

For any temporary accounts returned by the previous query:
Enter "Get-ADUser -Identity [Name] -Property WhenCreated" to determine when the account was created.

If the "WhenCreated" date and "AccountExpirationDate" from the previous query are greater than 3 days apart, this is a finding.

Member servers and standalone systems:

Enter "Net User [username]", where [username] is the name of the temporary user account.

If "Account expires" has not been defined within 72 hours for any temporary user account, this is a finding.

If the "Password last set" date and "Account expires" date are greater than 72 hours apart, this is a finding. (Net User does not provide an account creation date.)'
  desc 'fix', 'Configure temporary user accounts to automatically expire within 72 hours.

Domain account can be configured with an account expiration date, under "Account" properties.

Local accounts can be configured to expire with the command "Net user [username] /expires:[mm/dd/yyyy]", where username is the name of the temporary user account.

Delete any temporary user accounts that are no longer necessary.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27138r471659_chk'
  tag severity: 'medium'
  tag gid: 'V-225439'
  tag rid: 'SV-225439r569185_rule'
  tag stig_id: 'WN12-GE-000056'
  tag gtitle: 'SRG-OS-000002-GPOS-00002'
  tag fix_id: 'F-27126r471660_fix'
  tag 'documentable'
  tag legacy: ['SV-72063', 'V-57653']
  tag cci: ['CCI-000016']
  tag nist: ['AC-2 (2)']
end
