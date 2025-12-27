control 'SV-235735' do
  title 'Importing of home page settings must be disabled.'
  desc 'Allows users to import their home page setting from another browser into Microsoft Edge.

If this policy is enabled, the option to manually import the home page setting is automatically selected.

If this policy is disabled, the home page setting is not imported at first run, and users cannot import it manually.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of home page settings" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "ImportHomepage" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of home page settings" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38954r626401_chk'
  tag severity: 'medium'
  tag gid: 'V-235735'
  tag rid: 'SV-235735r626523_rule'
  tag stig_id: 'EDGE-00-000018'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38917r626402_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
