control 'SV-45269' do
  title 'Legacy filter functionality must be disallowed (Internet zone).'
  desc 'This policy setting specifies whether Internet Explorer renders legacy visual filters in this zone. If you enable this policy setting, you can control whether or not Internet Explorer renders legacy filters by selecting Enable, or Disable under Options in Group Policy Editor. If you disable, or do not configure this policy setting, users can choose whether or not to render filters in this zone. Users can change this setting on the Security tab of the Internet Options dialog box. Filters are not rendered by default in this zone.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Internet Zone "Render Legacy Filters" must be "Enabled", and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3 

Criteria: If the value 270B is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Internet Zone "Render Legacy Filters" to "Enabled", and select "Disable".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42616r1_chk'
  tag severity: 'medium'
  tag gid: 'V-34489'
  tag rid: 'SV-45269r1_rule'
  tag stig_id: 'DTBI1045'
  tag gtitle: 'DTBI1045 - Legacy filters (Internet zone).'
  tag fix_id: 'F-38665r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
