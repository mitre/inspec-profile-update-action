control 'SV-235733' do
  title 'Importing of extensions must be disabled.'
  desc 'Allows users to import extensions from another browser into Microsoft Edge.

If this policy is enabled, the Extensions check box is automatically selected in the Import browser data dialog box.

If this policy is disabled, extensions are not imported at first run, and users cannot import them manually.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of extensions" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "ImportExtensions" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of extensions" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38952r626395_chk'
  tag severity: 'medium'
  tag gid: 'V-235733'
  tag rid: 'SV-235733r626523_rule'
  tag stig_id: 'EDGE-00-000016'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38915r626396_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
