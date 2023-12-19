control 'SV-225335' do
  title 'Device driver updates must only search managed servers, not Windows Update.'
  desc 'Uncontrolled system updates can introduce issues to a system.  Obtaining update components from an outside source may also potentially provide sensitive information outside of the enterprise.  Device driver updates must be obtained from an internal source.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\DriverSearching\\

Value Name: DriverServerSelection

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Specify the search server for device driver updates" to "Enabled" with "Search Managed Server" selected.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27034r471347_chk'
  tag severity: 'low'
  tag gid: 'V-225335'
  tag rid: 'SV-225335r569185_rule'
  tag stig_id: 'WN12-CC-000025'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-27022r471348_fix'
  tag 'documentable'
  tag legacy: ['SV-51607', 'V-36678']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
