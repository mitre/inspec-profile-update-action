control 'SV-223036' do
  title 'Dragging of content from different domains within a window must be disallowed (Restricted Sites zone).'
  desc 'This policy setting allows you to set options for dragging content from one domain to a different domain when the source and destination are in the same window. If you enable this policy setting, users can drag content from one domain to a different domain when the source and destination are in the same window. Users cannot change this setting. If you disable this policy setting, users cannot drag content from one domain to a different domain when the source and destination are in the same window. Users cannot change this setting in the Internet Options dialog box. If you do not configure this policy setting, users cannot drag content from one domain to a different domain when the source and destination are in the same window. Users can change this setting in the Internet Options dialog box.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Restricted Sites Zone 'Enable dragging of content from different domains within a window' must be 'Enabled', and 'Disabled' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "2708" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Restricted Sites Zone 'Enable dragging of content from different domains within a window' to 'Enabled', and select 'Disabled' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24709r428658_chk'
  tag severity: 'medium'
  tag gid: 'V-223036'
  tag rid: 'SV-223036r879534_rule'
  tag stig_id: 'DTBI1025-IE11'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-24697r428659_fix'
  tag 'documentable'
  tag legacy: ['SV-59419', 'V-46555']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
