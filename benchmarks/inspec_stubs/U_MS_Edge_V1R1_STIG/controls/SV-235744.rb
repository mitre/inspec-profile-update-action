control 'SV-235744' do
  title 'Web Bluetooth API must be disabled.'
  desc "Control whether websites can access nearby Bluetooth devices. Access can be blocked completely or the site required to ask the user each time it wants to access a Bluetooth device.

If this policy is not configured, the default value ('AskWebBluetooth', meaning users are asked each time) is used and users can change it.

Policy options mapping:
- BlockWebBluetooth (2) = Do not allow any site to request access to Bluetooth devices via the Web Bluetooth API.
- AskWebBluetooth (3) = Allow sites to ask the user to grant access to a nearby Bluetooth device."
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Content settings/Control use of the Web Bluetooth API" must be set to "enabled" with the option value set to "Do not allow any site to request access to Bluetooth devices via the Web Bluetooth API".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "DefaultWebBluetoothGuardSetting" is not set to "REG_DWORD = 2", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Content settings/Control use of the Web Bluetooth API" to "enabled" with the option value set to "Do not allow any site to request access to Bluetooth devices via the Web Bluetooth API.'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38963r626428_chk'
  tag severity: 'medium'
  tag gid: 'V-235744'
  tag rid: 'SV-235744r626523_rule'
  tag stig_id: 'EDGE-00-000027'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38926r626521_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
