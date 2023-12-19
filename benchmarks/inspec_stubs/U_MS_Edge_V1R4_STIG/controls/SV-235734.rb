control 'SV-235734' do
  title 'Importing of browsing history must be disabled.'
  desc 'Allows users to import their browsing history from another browser into Microsoft Edge.

If this policy is enabled, the Browsing history check box is automatically selected in the Import browser data dialog box.

If this policy is disabled, browsing history data is not imported at first run, and users cannot import this data manually.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of browsing history" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "ImportHistory" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of browsing history" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38953r626538_chk'
  tag severity: 'medium'
  tag gid: 'V-235734'
  tag rid: 'SV-235734r626540_rule'
  tag stig_id: 'EDGE-00-000017'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38916r626539_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
