control 'SV-223098' do
  title 'Websites in less privileged web content zones must be prevented from navigating into the Restricted Sites zone.'
  desc 'This policy setting allows you to manage whether websites from less privileged zones, such as Restricted Sites, can navigate into the Restricted zone. If this policy setting is enabled, websites from less privileged zones can open new windows in, or navigate into, this zone. The security zone will run without the added layer of security that is provided by the Protection from Zone Elevation security feature. If Prompt is selected in the drop-down box, a warning is issued to the user that potentially risky navigation is about to occur. If this policy setting is disabled, the potentially risky navigation is prevented. The Internet Explorer security feature will be on in this zone as set by the Protection from Zone Elevation feature control. If this policy setting is not configured, websites from less privileged zones can open new windows in, or navigate into, this zone.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Web sites in less privileged Web content zones can navigate into this zone' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "2101" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Web sites in less privileged Web content zones can navigate into this zone' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24771r428844_chk'
  tag severity: 'medium'
  tag gid: 'V-223098'
  tag rid: 'SV-223098r428846_rule'
  tag stig_id: 'DTBI520-IE11'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-24759r428845_fix'
  tag 'documentable'
  tag legacy: ['SV-59559', 'V-46695']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
