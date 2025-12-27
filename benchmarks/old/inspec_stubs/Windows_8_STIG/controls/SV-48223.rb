control 'SV-48223' do
  title 'Event Viewer Events.asp links must be turned off.'
  desc 'Viewing events is a function of administrators, who must not access the internet with privileged accounts.  This setting will disable  Events.asp hyperlinks in Event Viewer to prevent links to the internet from within events.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\EventViewer\\

Value Name: MicrosoftEventVwrDisableLinks

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off Event Viewer "Events.asp" links" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44902r1_chk'
  tag severity: 'low'
  tag gid: 'V-15672'
  tag rid: 'SV-48223r1_rule'
  tag stig_id: 'WN08-CC-000033'
  tag gtitle: 'Event Viewer Events.asp Links'
  tag fix_id: 'F-41359r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
