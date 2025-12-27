control 'SV-235742' do
  title 'WebUSB must be disabled.'
  desc "Set whether websites can access connected USB devices. Access can be blocked completely or the user asked each time a website wants to get access to connected USB devices.

Override this policy for specific URL patterns by using the WebUsbAskForUrls and WebUsbBlockedForUrls policies.

If this policy is not configured, sites can ask users whether they can access the connected USB devices ('AskWebUsb') by default, and users can change this setting."
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Content settings/Control use of the WebUSB API" must be set to "enabled" with the option value set to "Do not allow any site to request access to USB devices via the WebUSB API".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "DefaultWebUsbGuardSetting" is not set to "REG_DWORD = 2", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Content settings/Control use of the WebUSB API" to enabled" and select "Do not allow any site to request access to USB devices via the WebUSB API".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38961r626422_chk'
  tag severity: 'medium'
  tag gid: 'V-235742'
  tag rid: 'SV-235742r626523_rule'
  tag stig_id: 'EDGE-00-000025'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38924r626423_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
