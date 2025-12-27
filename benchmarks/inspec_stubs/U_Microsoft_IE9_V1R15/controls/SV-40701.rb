control 'SV-40701' do
  title 'First Run Customize settings must be enabled as home page.'
  desc 'This policy setting prevents performance of the First Run Customize settings ability and provides central management controls of what web page will be provided to the user when they launch Internet Explorer for the first time after installation of Internet Explorer. If you enable this policy setting, you can configure one of two choices: 
1) Skip Customize Settings, and go directly to the user’s home page, or 
2) Skip Customize Settings, and go directly to the "Welcome to Internet Explorer" Web page. 
If you disable or do not configure this policy setting, users go through the regular first run process.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Prevent performance of First Run Customize settings" must be “Enabled” and "Go directly to home page" selected from the drop-down box.

Procedure: Use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Main 

Criteria: If the value DisableFirstRunCustomize is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Prevent performance of First Run Customize settings" to “Enabled” and select "Go directly to home page" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39428r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17296'
  tag rid: 'SV-40701r1_rule'
  tag stig_id: 'DTBI010'
  tag gtitle: 'DTBI010 - Prevent performance of First Run Customize setting'
  tag fix_id: 'F-34557r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECSC-1'
end
