control 'SV-253426' do
  title 'Windows 11 Kernel (Direct Memory Access) DMA Protection must be enabled.'
  desc 'Kernel DMA Protection to protect PCs against drive-by Direct Memory Access (DMA) attacks using PCI hot plug devices connected to Thunderbolt 3 ports. Drive-by DMA attacks can lead to disclosure of sensitive information residing on a PC, or even injection of malware that allows attackers to bypass the lock screen or control PCs remotely.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Kernel DMA Protection

Value Name: DeviceEnumerationPolicy
Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Kernel DMA Protection >> "Enumeration policy for external devices incompatible with Kernel DMA Protection" to "Enabled" with "Enumeration Policy" set to "Block All".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56879r829360_chk'
  tag severity: 'medium'
  tag gid: 'V-253426'
  tag rid: 'SV-253426r829362_rule'
  tag stig_id: 'WN11-EP-000310'
  tag gtitle: 'SRG-OS-000471-GPOS-00216'
  tag fix_id: 'F-56829r829361_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
