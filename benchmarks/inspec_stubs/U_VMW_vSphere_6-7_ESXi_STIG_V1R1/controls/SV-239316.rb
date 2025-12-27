control 'SV-239316' do
  title 'The ESXi host must prevent unintended use of the dvFilter network APIs.'
  desc 'If the organization is not using products that use the dvfilter network API, the host should not be configured to send network information to a VM. 

If the API is enabled, an attacker might attempt to connect a VM to it, potentially providing access to the network of other VMs on the host. If the organization is using a product that uses this API, verify that the host has been configured correctly. If the organization is not using such a product, ensure the setting is blank.'
  desc 'check', 'From the vSphere Client, select the ESXi host and go to Configure >> System >> Advanced System Settings. 

Select the "Net.DVFilterBindIpAddress" value and verify the value is blank or the correct IP address of a security appliance if in use.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress

If the "Net.DVFilterBindIpAddress" is not blank and security appliances are not in use on the host, this is a finding.'
  desc 'fix', 'From the vSphere Client, select the ESXi Host and go to Configure >> System >> Advanced System Settings. 

Click "Edit", select the "Net.DVFilterBindIpAddress" value, and remove any incorrect addresses.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress | Set-AdvancedSetting -Value ""'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 ESXi'
  tag check_id: 'C-42549r674875_chk'
  tag severity: 'medium'
  tag gid: 'V-239316'
  tag rid: 'SV-239316r674877_rule'
  tag stig_id: 'ESXI-67-000062'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-42508r674876_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
