control 'SV-225342' do
  title 'Event Viewer Events.asp links must be turned off.'
  desc 'Viewing events is a function of administrators, who must not access the internet with privileged accounts.  This setting will disable  Events.asp hyperlinks in Event Viewer to prevent links to the internet from within events.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\EventViewer\\

Value Name: MicrosoftEventVwrDisableLinks

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off Event Viewer "Events.asp" links" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27041r471368_chk'
  tag severity: 'low'
  tag gid: 'V-225342'
  tag rid: 'SV-225342r569185_rule'
  tag stig_id: 'WN12-CC-000033'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27029r471369_fix'
  tag 'documentable'
  tag legacy: ['V-15672', 'SV-53017']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
