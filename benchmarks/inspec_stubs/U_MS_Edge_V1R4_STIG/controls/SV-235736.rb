control 'SV-235736' do
  title 'Importing of open tabs must be disabled.'
  desc 'Allows users to import open and pinned tabs from another browser into Microsoft Edge.

If this policy is enabled, the Open tabs check box is automatically selected in the Import browser data dialog box.

If this policy is disabled, open tabs are not imported at first run, and users cannot import them manually.

If this policy is not configured, open tabs are imported at first run, and users can choose whether to import them manually during later browsing sessions.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of open tabs" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "ImportOpenTabs" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of open tabs" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38955r626404_chk'
  tag severity: 'medium'
  tag gid: 'V-235736'
  tag rid: 'SV-235736r626523_rule'
  tag stig_id: 'EDGE-00-000019'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38918r626405_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
