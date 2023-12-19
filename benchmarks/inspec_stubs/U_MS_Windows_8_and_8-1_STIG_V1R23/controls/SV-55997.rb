control 'SV-55997' do
  title 'The option to update to the latest version of Windows from the Store must be turned off.'
  desc 'Uncontrolled system updates can introduce issues into the environment.  Updates to the latest version of Windows must be done through proper change management.  This setting will prevent the option to update to the latest version of Windows from being offered through the Store.'
  desc 'check', 'Verify the registry value below. If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\WindowsStore\\

Value Name: DisableOSUpgrade

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Store >> "Turn off the offer to update to the latest version of Windows" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-66275r1_chk'
  tag severity: 'medium'
  tag gid: 'V-43244'
  tag rid: 'SV-55997r3_rule'
  tag stig_id: 'WN08-CC-000144'
  tag gtitle: 'WINCC-000144'
  tag fix_id: 'F-71663r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
