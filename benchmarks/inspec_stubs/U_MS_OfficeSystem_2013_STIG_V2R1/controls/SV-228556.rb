control 'SV-228556' do
  title 'Connection verification of permissions must be enforced.'
  desc "Users are not required to connect to the network to verify permissions. If users do not need their licenses confirmed when attempting to open Office documents, they might be able to access documents after their licenses have been revoked. Also, it is not possible to log the usage of files with restricted permissions if users' licenses are not confirmed."
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Manage Restricted Permissions "Always require users to connect to verify permission" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\drm

Criteria: If the value 'RequireConnection' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Manage Restricted Permissions "Always require users to connect to verify permission" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30789r498946_chk'
  tag severity: 'medium'
  tag gid: 'V-228556'
  tag rid: 'SV-228556r508020_rule'
  tag stig_id: 'DTOO201'
  tag gtitle: 'SRG-APP-000340'
  tag fix_id: 'F-30774r498947_fix'
  tag 'documentable'
  tag legacy: ['V-17731', 'SV-52750']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
