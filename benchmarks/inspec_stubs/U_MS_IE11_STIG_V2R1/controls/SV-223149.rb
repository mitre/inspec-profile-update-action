control 'SV-223149' do
  title 'Dragging of content from different domains across windows must be disallowed (Internet zone).'
  desc 'This policy setting allows you to set options for dragging content from one domain to a different domain when the source and destination are in different windows. If you enable this policy setting, users can drag content from one domain to a different domain when the source and destination are in different windows. Users cannot change this setting. If you disable this policy setting, users cannot drag content from one domain to a different domain when both the source and destination are in different windows. Users cannot change this setting. If you do not configure this policy setting, users cannot drag content from one domain to a different domain when the source and destination are in different windows. Users can change this setting in the Internet Options dialog box.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Internet Zone 'Enable dragging of content from different domains across windows' must be 'Enabled', and 'Disabled' selected from the drop-down box. Procedure: Use the windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value "2709" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Internet Zone 'Enable dragging of content from different domains across windows' to 'Enabled', and select 'Disabled' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24822r428997_chk'
  tag severity: 'medium'
  tag gid: 'V-223149'
  tag rid: 'SV-223149r428999_rule'
  tag stig_id: 'DTBI990-IE11'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-24810r428998_fix'
  tag 'documentable'
  tag legacy: ['SV-59847', 'V-46981']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
