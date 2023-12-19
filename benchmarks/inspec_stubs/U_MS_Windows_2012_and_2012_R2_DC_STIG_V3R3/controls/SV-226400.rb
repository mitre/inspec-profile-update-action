control 'SV-226400' do
  title 'The Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Allow log on through Remote Desktop Services" user right can access a system through Remote Desktop.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Allow log on through Remote Desktop Services" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Allow log on through Remote Desktop Services" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28104r477049_chk'
  tag severity: 'medium'
  tag gid: 'V-226400'
  tag rid: 'SV-226400r794631_rule'
  tag stig_id: 'WN12-UR-000006-DC'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-28092r477050_fix'
  tag 'documentable'
  tag legacy: ['SV-53119', 'V-26473']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
