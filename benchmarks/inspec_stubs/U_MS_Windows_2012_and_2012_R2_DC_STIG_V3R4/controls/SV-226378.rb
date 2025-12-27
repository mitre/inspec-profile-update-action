control 'SV-226378' do
  title 'The Create permanent shared objects user right must not be assigned to any groups or accounts.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Create permanent shared objects" user right could expose sensitive data by creating shared objects.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups are granted the "Create permanent shared objects" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create permanent shared objects" to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28081r476980_chk'
  tag severity: 'medium'
  tag gid: 'V-226378'
  tag rid: 'SV-226378r794655_rule'
  tag stig_id: 'WN12-UR-000014'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-28069r476981_fix'
  tag 'documentable'
  tag legacy: ['SV-53059', 'V-26481']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
