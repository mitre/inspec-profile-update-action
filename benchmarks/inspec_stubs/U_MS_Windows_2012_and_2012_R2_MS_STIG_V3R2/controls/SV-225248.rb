control 'SV-225248' do
  title 'Windows 2012/2012 R2 manually managed application account passwords must be changed at least annually or when a system administrator with knowledge of the password leaves the organization.'
  desc 'Setting application accounts to expire may cause applications to stop functioning. However, not changing them on a regular basis exposes them to attack. If managed service accounts are used, this alleviates the need to manually change application account passwords.'
  desc 'check', %q(Determine if manually managed application/service accounts exist. If none exist, this is NA.

If passwords for manually managed application/service accounts are not changed at least annually or when an administrator with knowledge of the password leaves the organization, this is a finding.

Identify manually managed application/service accounts.

To determine the date a password was last changed:

Domain controllers:

Open "Windows PowerShell".

Enter "Get-ADUser -Identity [application account name] -Properties PasswordLastSet | FL Name, PasswordLastSet", where [application account name] is the name of the manually managed application/service account.

If the "PasswordLastSet" date is more than one year old, this is a finding.

Member servers and standalone systems:

Open "Windows PowerShell" or "Command Prompt".

Enter 'Net User [application account name] | Find /i "Password Last Set"', where [application account name] is the name of the manually managed application/service account.

If the "Password Last Set" date is more than one year old, this is a finding.)
  desc 'fix', 'Change passwords for manually managed application/service accounts at least annually or when an administrator with knowledge of the password leaves the organization.

It is recommended that system-managed service accounts be used where possible.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-26947r471086_chk'
  tag severity: 'medium'
  tag gid: 'V-225248'
  tag rid: 'SV-225248r569185_rule'
  tag stig_id: 'WN12-00-000011'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26935r471087_fix'
  tag 'documentable'
  tag legacy: ['SV-51580', 'V-36662']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
