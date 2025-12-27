control 'SV-235731' do
  title 'Importing of browser settings must be disabled.'
  desc 'Allows users to import browser settings from another browser into Microsoft Edge.

If this policy is enabled, the Browser settings check box is automatically selected in the Import browser data dialog box.

If this policy is disabled, browser settings are not imported at first run, and users cannot import them manually.

If this policy is not configured, browser settings are imported at first run, and users can choose whether to import them manually during later browsing sessions.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of browser settings" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "ImportBrowserSettings" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of browser settings" to "disabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38950r626389_chk'
  tag severity: 'low'
  tag gid: 'V-235731'
  tag rid: 'SV-235731r626523_rule'
  tag stig_id: 'EDGE-00-000014'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38913r626390_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
