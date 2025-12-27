control 'SV-40614' do
  title 'Navigating windows and frames across different domains must be disallowed (Restricted Sites zone).'
  desc 'Frames navigating across different domains are a security concern, because the user may think they are accessing pages on one site while they are actually accessing pages on another site. It is possible that a web site hosting malicious content could use this feature in a manner similar to cross site scripting. This policy setting allows you to manage the opening of sub-frames and access of applications across different domains.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Navigate windows and frames across different domains" must be “Enabled” and "Disable" selected from the drop-down box.

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 1607 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Navigate windows and frames across different domains" to “Enabled” and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39357r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6304'
  tag rid: 'SV-40614r1_rule'
  tag stig_id: 'DTBI129'
  tag gtitle: 'DTBI129 - Navigating across domains - Restricted'
  tag fix_id: 'F-34468r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
