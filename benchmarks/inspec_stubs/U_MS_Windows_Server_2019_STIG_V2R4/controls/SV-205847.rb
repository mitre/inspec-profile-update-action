control 'SV-205847' do
  title 'Windows Server 2019 manually managed application account passwords must be changed at least annually or when a system administrator with knowledge of the password leaves the organization.'
  desc 'Setting application account passwords to expire may cause applications to stop functioning. However, not changing them on a regular basis exposes them to attack. If managed service accounts are used, this alleviates the need to manually change application account passwords.'
  desc 'check', %q(Determine if manually managed application/service accounts exist. If none exist, this is NA.

If passwords for manually managed application/service accounts are not changed at least annually or when an administrator with knowledge of the password leaves the organization, this is a finding.

Identify manually managed application/service accounts.

To determine the date a password was last changed:

Domain controllers:

Open "PowerShell".

Enter "Get-AdUser -Identity [application account name] -Properties PasswordLastSet | FT Name, PasswordLastSet", where [application account name] is the name of the manually managed application/service account.

If the "PasswordLastSet" date is more than one year old, this is a finding.


Member servers and standalone systems:

Open "Command Prompt".

Enter 'Net User [application account name] | Find /i "Password Last Set"', where [application account name] is the name of the manually managed application/service account.

If the "Password Last Set" date is more than one year old, this is a finding.)
  desc 'fix', 'Change passwords for manually managed application/service accounts at least annually or when an administrator with knowledge of the password leaves the organization.

It is recommended that system-managed service accounts be used whenever possible.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-6112r355903_chk'
  tag severity: 'medium'
  tag gid: 'V-205847'
  tag rid: 'SV-205847r569188_rule'
  tag stig_id: 'WN19-00-000060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-6112r355904_fix'
  tag 'documentable'
  tag legacy: ['SV-103297', 'V-93209']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
