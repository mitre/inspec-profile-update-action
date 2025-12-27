control 'SV-45143' do
  title 'Dragging of content from different domains across windows must be disallowed (Restricted Sites zone).'
  desc 'This policy setting allows you to set options for dragging content from one domain to a different domain when the source and destination are in different windows. If you enable this policy setting, users can drag content from one domain to a different domain when the source and destination are in different windows. Users cannot change this setting. If you enable this policy setting, users cannot drag content from one domain to a different domain when both the source and destination are in different windows. Users cannot change this setting. If you do not configure this policy setting, users cannot drag content from one domain to a different domain when the source and destination are in different windows. Users can change this setting in the Internet Options dialog.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Restricted Sites Zone "Enable dragging of content from different domains across windows" must be "Enabled", and "Disabled" selected. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 2709 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Restricted Sites Zone "Enable dragging of content from different domains across windows" to "Enabled", and select "Disabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42486r1_chk'
  tag severity: 'medium'
  tag gid: 'V-34458'
  tag rid: 'SV-45143r1_rule'
  tag stig_id: 'DTBI1005'
  tag gtitle: 'DTBI1005 - Content from different domains across windows - Restricted zone'
  tag fix_id: 'F-38539r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
