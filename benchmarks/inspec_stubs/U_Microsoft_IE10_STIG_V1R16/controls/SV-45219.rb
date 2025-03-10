control 'SV-45219' do
  title 'Internet Explorer must be configured to make proxy settings per user.'
  desc 'This setting controls whether or not the Internet Explorer proxy settings are configured on a per-user or per-machine basis. If you enable this policy, users cannot set user specific proxy settings. They must use the zones created for all users of the computer. If you disable this policy or do not configure it, users of the same computer can establish their own proxy settings. This policy is intended to ensure that proxy settings apply uniformly to the same computer and do not vary from user to user.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer "Make proxy settings per-machine (rather than per user)" must be "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings 

Criteria: If the value ProxySettingsPerUser is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer "Make proxy settings per-machine (rather than per user)" to "Disabled".'
  impact 0.3
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42567r1_chk'
  tag severity: 'low'
  tag gid: 'V-3430'
  tag rid: 'SV-45219r1_rule'
  tag stig_id: 'DTBI367'
  tag gtitle: 'DTBI367 - Proxy settings'
  tag fix_id: 'F-38615r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
