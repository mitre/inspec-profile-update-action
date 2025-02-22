control 'SV-45454' do
  title 'URL Suggestions must be disallowed.'
  desc 'This policy setting turns off URL Suggestions. URL Suggestions allow users to auto complete URLs in the address bar based on common URLs. The list of common URLs is stored locally and is updated once a month. No user data is sent over the internet by this feature. If you enable this policy setting, URL Suggestions will be turned off. Users will not be able to turn on URL Suggestions. If you disable this policy setting, URL Suggestions will be turned on. Users will not be able to turn off URL Suggestions. If you do not configure this policy setting, URL Suggestions will be turned on. Users will be able to turn on or turn off URL Suggestions in the Internet Options dialog.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Settings-> AutoComplete "Turn off URL Suggestions" must be "Enabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\DomainSuggestion 

Criteria: If the value Enabled is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Settings-> AutoComplete "Turn off URL Suggestions" to "Enabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42803r1_chk'
  tag severity: 'medium'
  tag gid: 'V-34590'
  tag rid: 'SV-45454r1_rule'
  tag stig_id: 'DTBI1030'
  tag gtitle: 'DTBI1030 - URL Suggestions'
  tag fix_id: 'F-38851r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
