control 'SV-228540' do
  title 'Roaming settings must be stored locally and not synchronized to the Microsoft Office roaming settings web service.'
  desc 'Microsoft Office includes the ability to roam settings for specific Office features amongst devices by storing this data in the cloud. This data includes user activity such as the list of most recently used documents as well as user preferences such as the Office theme. This policy setting controls whether this data is allowed to be stored in the cloud. If this policy setting is enabled, roaming settings are only stored locally and not synchronized to the Microsoft Office roaming settings web service. If this policy setting is disabled or not configured, roaming settings are synchronized with the Microsoft Office roaming settings web service and users can access their data from other devices. Existing data in the cloud is not affected by this policy.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Services >> "Disable Roaming Office User Settings" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\roaming

If the value 'roamingsettingsdisabled' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Services >> "Disable Roaming Office User Settings" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30773r498898_chk'
  tag severity: 'medium'
  tag gid: 'V-228540'
  tag rid: 'SV-228540r508020_rule'
  tag stig_id: 'DTOO414'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30758r498899_fix'
  tag 'documentable'
  tag legacy: ['V-40884', 'SV-53216']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
