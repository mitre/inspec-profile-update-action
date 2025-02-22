control 'SV-223040' do
  title 'Prevent bypassing SmartScreen Filter warnings about files that are not commonly downloaded from the internet must be enabled.'
  desc 'This policy setting determines whether the user can bypass warnings from SmartScreen Filter. SmartScreen Filter warns the user about executable files that Internet Explorer users do not commonly download from the internet. If you enable this policy setting, SmartScreen Filter warnings block the user. If you disable or do not configure this policy setting, the user can bypass SmartScreen Filter warnings.'
  desc 'check', 'If the system is on the SIPRNet, this requirement is NA.

The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> ”Prevent bypassing SmartScreen Filter warnings about files that are not commonly downloaded from the internet” must be ”Enabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\PhishingFilter.

Criteria: If the value "PreventOverrideAppRepUnknown" is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'If the system is on the SIPRNet, this requirement is NA.

Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> ”Prevent bypassing SmartScreen Filter warnings about files that are not commonly downloaded from the internet” to ”Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24713r428670_chk'
  tag severity: 'medium'
  tag gid: 'V-223040'
  tag rid: 'SV-223040r428672_rule'
  tag stig_id: 'DTBI1065-IE11'
  tag gtitle: 'SRG-APP-000209'
  tag fix_id: 'F-24701r428671_fix'
  tag 'documentable'
  tag legacy: ['SV-79203', 'V-64713']
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
