control 'SV-21932' do
  title 'Event Viewer Events.asp links must be turned off.'
  desc 'Viewing events is a function of administrators, who must not access the internet with privileged accounts. This setting will disable Events.asp hyperlinks in Event Viewer to prevent links to the internet from within events.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\Software\\Policies\\Microsoft\\EventViewer\\

Value Name:  MicrosoftEventVwrDisableLinks

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings “Turn off Event Viewer “Events.asp” links” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-24459r2_chk'
  tag severity: 'low'
  tag gid: 'V-15672'
  tag rid: 'SV-21932r2_rule'
  tag gtitle: 'Event Viewer Events.asp Links'
  tag fix_id: 'F-20476r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
