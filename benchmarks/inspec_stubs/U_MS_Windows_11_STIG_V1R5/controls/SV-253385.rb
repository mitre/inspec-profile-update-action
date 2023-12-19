control 'SV-253385' do
  title 'The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. This setting will prevent the Program Inventory from collecting data about a system and sending the information to Microsoft.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\\

Value Name: DisableInventory

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Application Compatibility >> "Turn off Inventory Collector" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56838r829237_chk'
  tag severity: 'low'
  tag gid: 'V-253385'
  tag rid: 'SV-253385r829239_rule'
  tag stig_id: 'WN11-CC-000175'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56788r829238_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
