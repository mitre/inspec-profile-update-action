control 'SV-225328' do
  title 'Optional component installation and component repair must be prevented from using Windows Update.'
  desc 'Uncontrolled system updates can introduce issues to a system.  Obtaining update components from an outside source may also potentially provide sensitive information outside of the enterprise.  Optional component installation or repair must be obtained from an internal source.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Servicing\\

Value Name: UseWindowsUpdate

Type: REG_DWORD
Value: 2'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> "Specify settings for optional component installation and component repair" to "Enabled" and with "Never attempt to download payload from Windows Update" selected.'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27027r471326_chk'
  tag severity: 'low'
  tag gid: 'V-225328'
  tag rid: 'SV-225328r569185_rule'
  tag stig_id: 'WN12-CC-000018'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-27015r471327_fix'
  tag 'documentable'
  tag legacy: ['SV-51606', 'V-36677']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
