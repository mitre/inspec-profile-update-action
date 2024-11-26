control 'SV-235743' do
  title 'Google Cast must be disabled.'
  desc 'Enable this policy to enable Google Cast. Users will be able to launch it from the app menu, page context menus, media controls on Cast-enabled websites, and (if shown) the Cast toolbar icon.

Disable this policy to disable Google Cast.

By default, Google Cast is enabled.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Cast/Enable Google Cast" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "EnableMediaRouter" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Cast/Enable Google Cast" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38962r626425_chk'
  tag severity: 'medium'
  tag gid: 'V-235743'
  tag rid: 'SV-235743r626523_rule'
  tag stig_id: 'EDGE-00-000026'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38925r626426_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
