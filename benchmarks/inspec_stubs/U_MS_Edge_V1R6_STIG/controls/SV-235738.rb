control 'SV-235738' do
  title 'Importing of saved passwords must be disabled.'
  desc 'Allows users to import saved passwords from another browser into Microsoft Edge.

If this policy is enabled, the option to manually import saved passwords is automatically selected.

If this policy is disabled, saved passwords are not imported on first run, and users cannot import them manually.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of saved passwords" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "ImportSavedPasswords" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of saved passwords" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38957r626410_chk'
  tag severity: 'medium'
  tag gid: 'V-235738'
  tag rid: 'SV-235738r626523_rule'
  tag stig_id: 'EDGE-00-000021'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38920r626411_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
