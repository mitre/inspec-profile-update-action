control 'SV-40657' do
  title 'Web sites in less privileged web content zones must be disallowed to navigate into the Restricted Site zone.'
  desc 'This policy setting allows you to manage whether web sites from less privileged zones, such as Restricted Sites, can navigate into this zone. If you enable this policy setting, web sites from less privileged zones can open new windows in, or navigate into, this zone. The security zone will run without the added layer of security that is provided by the Protection from Zone Elevation security feature. If you select Prompt in the drop-down box, a warning is issued to the user that potentially risky navigation is about to occur. If you disable this policy setting, the possibly harmful navigations are prevented. The Internet Explorer security feature will be on in this zone as set by Protection from Zone Elevation feature control. If you do not configure this policy setting, web sites from less privileged zones can open new windows in, or navigate into, this zone.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Web sites in less privileged Web content zones can navigate into this zone" must be “Enabled” and "Disable" selected from the drop-down box.

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 2101 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Web sites in less privileged Web content zones can navigate into this zone" to “Enabled” and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39395r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15534'
  tag rid: 'SV-40657r1_rule'
  tag stig_id: 'DTBI520'
  tag gtitle: 'DTBI520 - Less privileged web content - Restricted'
  tag fix_id: 'F-34513r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECSC-1'
end
