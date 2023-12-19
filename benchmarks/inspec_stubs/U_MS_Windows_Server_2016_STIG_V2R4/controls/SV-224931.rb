control 'SV-224931' do
  title 'The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and will prevent uncontrolled updates to the system.

This setting will prevent the Program Inventory from collecting data about a system and sending the information to Microsoft.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\\

Value Name: DisableInventory

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Application Compatibility >> "Turn off Inventory Collector" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26622r465695_chk'
  tag severity: 'low'
  tag gid: 'V-224931'
  tag rid: 'SV-224931r569186_rule'
  tag stig_id: 'WN16-CC-000240'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-26610r465696_fix'
  tag 'documentable'
  tag legacy: ['V-73543', 'SV-88207']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
