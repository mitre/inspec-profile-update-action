control 'SV-45144' do
  title 'Dragging of content from different domains within a window must be disallowed (Internet zone).'
  desc 'This policy setting allows you to set options for dragging content from one domain to a different domain when the source and destination are in the same window. If you enable this policy setting, users can drag content from one domain to a different domain when the source and destination are in the same window. Users cannot change this setting. If you disable this policy setting, users cannot drag content from one domain to a different domain when the source and destination are in the same window. Users cannot change this setting in the Internet Options dialog. If you do not configure this policy setting, users cannot drag content from one domain to a different domain when the source and destination are in the same window. Users can change this setting in the Internet Options dialog.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Internet Zone "Enable dragging of content from different domains within a window" must be "Enabled", and "Disabled" selected. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3 

Criteria: If the value 2708 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Internet Zone "Enable dragging of content from different domains within a window" to "Enabled", and select "Disabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42487r1_chk'
  tag severity: 'medium'
  tag gid: 'V-34459'
  tag rid: 'SV-45144r1_rule'
  tag stig_id: 'DTBI1000'
  tag gtitle: 'DTBI1000 - Content from different domains within windows - Internet zone'
  tag fix_id: 'F-38540r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
