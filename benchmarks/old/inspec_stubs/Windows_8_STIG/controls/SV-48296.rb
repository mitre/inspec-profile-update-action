control 'SV-48296' do
  title 'Optional component installation and component repair must be prevented from using Windows Update.'
  desc 'Uncontrolled system updates can introduce issues to a system.  Obtaining update components from an outside source may also potentially provide sensitive information outside of the enterprise.  Optional component installation or repair must be obtained from an internal source.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Servicing \\

Value Name: UseWindowsUpdate

Type: REG_DWORD
Value: 2'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> "Specify settings for optional component installation and component repair" to "Enabled" and with "Never attempt to download payload from Windows Update" selected.'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44974r1_chk'
  tag severity: 'low'
  tag gid: 'V-36677'
  tag rid: 'SV-48296r2_rule'
  tag stig_id: 'WN08-CC-000018'
  tag gtitle: 'WINCC-000018'
  tag fix_id: 'F-41431r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
