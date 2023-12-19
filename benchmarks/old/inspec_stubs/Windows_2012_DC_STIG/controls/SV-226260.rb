control 'SV-226260' do
  title 'Windows 2012 / 2012 R2 must automatically remove or disable emergency accounts after the crisis is resolved or within 72 hours.'
  desc 'Emergency administrator accounts are privileged accounts which are established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.

Emergency administrator accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators when network or normal logon/access is not available). Infrequently used accounts are not subject to automatic termination dates. Emergency accounts are accounts created in response to crisis situations, usually for use by maintenance personnel. The automatic expiration or disabling time period may be extended as needed until the crisis is resolved; however, it must not be extended indefinitely. A permanent account should be established for privileged users who need long-term maintenance accounts.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Determine if emergency administrator accounts are used and identify any that exist. If none exist, this is NA.

If emergency administrator accounts cannot be configured with an expiration date due to an ongoing crisis, the accounts must be disabled or removed when the crisis is resolved.

If emergency administrator accounts have not been configured with an expiration date or have not been disabled or removed following the resolution of a crisis, this is a finding.

Domain Controllers:

Enter "Search-ADAccount -AccountExpiring -TimeSpan 3:00:00:00 | FT Name, AccountExpirationDate"
This will return any accounts configured to expire within the next 3 days.  (The "TimeSpan" value to can be changed to find accounts configured to expire at various times such as 30 for the next month.)

If any accounts identified as emergency administrator accounts are not listed, this is a finding.

For any emergency administrator accounts returned by the previous query:
Enter "Get-ADUser -Identity [Name] -Property WhenCreated" to determine when the account was created.

If the "WhenCreated" date and "AccountExpirationDate" from the previous query are greater than 3 days apart, this is a finding.

Member servers and standalone systems:

Enter "Net User [username]", where [username] is the name of the emergency administrator accounts.

If "Account expires" has not been defined within 72 hours for any emergency administrator accounts, this is a finding.

If the "Password last set" date and "Account expires" date are greater than 72 hours apart, this is a finding. (Net User does not provide an account creation date.)'
  desc 'fix', 'Remove emergency administrator accounts after a crisis has been resolved or configure the accounts to automatically expire within 72 hours.

Domain accounts can be configured with an account expiration date, under "Account" properties.

Local accounts can be configured to expire with the command "Net user [username] /expires:[mm/dd/yyyy]", where username is the name of the emergency administrator account.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27962r476624_chk'
  tag severity: 'medium'
  tag gid: 'V-226260'
  tag rid: 'SV-226260r794541_rule'
  tag stig_id: 'WN12-GE-000057'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag fix_id: 'F-27950r476625_fix'
  tag 'documentable'
  tag legacy: ['V-57655', 'SV-72065']
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end
