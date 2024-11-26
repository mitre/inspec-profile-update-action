control 'SV-226149' do
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
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27851r475770_chk'
  tag severity: 'low'
  tag gid: 'V-226149'
  tag rid: 'SV-226149r794468_rule'
  tag stig_id: 'WN12-CC-000018'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-27839r475771_fix'
  tag 'documentable'
  tag legacy: ['SV-51606', 'V-36677']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
