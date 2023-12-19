control 'SV-55993' do
  title 'The network selection user interface (UI) must not be displayed on the logon screen.'
  desc 'Enabling interaction with the network selection UI allows users to change connections to available networks without signing into Windows.'
  desc 'check', 'Verify the registry value below. If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

Value Name: DontDisplayNetworkSelectionUI

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Logon >> "Do not display network selection UI" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-66265r1_chk'
  tag severity: 'medium'
  tag gid: 'V-43240'
  tag rid: 'SV-55993r3_rule'
  tag stig_id: 'WN08-CC-000140'
  tag gtitle: 'WINCC-000140'
  tag fix_id: 'F-71653r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
