control 'SV-254348' do
  title 'Windows Server 2022 network selection user interface (UI) must not be displayed on the logon screen.'
  desc 'Enabling interaction with the network selection UI allows users to change connections to available networks without signing in to Windows.'
  desc 'check', 'Verify the registry value below. If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

Value Name: DontDisplayNetworkSelectionUI

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Logon >> Do not display network selection UI to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57833r848858_chk'
  tag severity: 'medium'
  tag gid: 'V-254348'
  tag rid: 'SV-254348r848860_rule'
  tag stig_id: 'WN22-CC-000170'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-57784r848859_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
