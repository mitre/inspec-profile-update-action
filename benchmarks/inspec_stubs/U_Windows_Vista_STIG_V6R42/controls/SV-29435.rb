control 'SV-29435' do
  title 'Event Viewer Events.asp Links'
  desc 'This check verifies that Events.asp hyperlinks in Event Viewer are available.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, then this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\EventViewer\\

Value Name:  MicrosoftEventVwrDisableLinks

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings “Turn off Event Viewer “Events.asp” links” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-15316r1_chk'
  tag severity: 'low'
  tag gid: 'V-15672'
  tag rid: 'SV-29435r1_rule'
  tag gtitle: 'Event Viewer Events.asp Links'
  tag fix_id: 'F-15539r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
