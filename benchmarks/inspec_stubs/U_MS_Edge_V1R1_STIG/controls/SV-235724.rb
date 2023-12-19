control 'SV-235724' do
  title 'Background processing must be disabled.'
  desc 'Background processing allows Microsoft Edge processes to start at OS sign-in and keep running after the last browser window is closed. In this scenario, background apps and the current browsing session remain active, including any session cookies. An open background process displays an icon in the system tray, and can be closed from there.

If this policy is enabled, background mode is turned on.

If this policy is disabled, background mode is turned off.

If this policy is not configured, background mode is initially turned off, and the user can configure its behavior in edge://settings/system.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Continue running background apps after Microsoft Edge closes" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\Recommended

If the value for "BackgroundModeEnabled" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Continue running background apps after Microsoft Edge closes" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38943r626368_chk'
  tag severity: 'medium'
  tag gid: 'V-235724'
  tag rid: 'SV-235724r626523_rule'
  tag stig_id: 'EDGE-00-000006'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38906r626369_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
