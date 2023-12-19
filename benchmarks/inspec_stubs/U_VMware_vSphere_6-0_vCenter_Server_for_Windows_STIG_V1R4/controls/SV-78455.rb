control 'SV-78455' do
  title 'The system must ensure the distributed port group MAC Address Change policy is set to reject.'
  desc 'If the virtual machine operating system changes the MAC address, it can send frames with an impersonated source MAC address at any time. This allows it to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network. This will prevent VMs from changing their effective MAC address. It will affect applications that require this functionality. This will also affect how a layer 2 bridge will operate. This will also affect applications that require a specific MAC address for licensing.'
  desc 'check', 'From the vSphere Client go to Home >> Networking. Select a distributed port group and click edit and go to security and verify "MAC Address Changes" is set to reject.

or

From a PowerCLI command prompt while connected to the vCenter server run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | Get-VDSecurityPolicy

If the "MAC Address Changes" policy is set to accept, this is a finding.'
  desc 'fix', 'From the vSphere Client go to Home >> Networking. Select a distributed port group and click edit and go to security and set "MAC Address Changes" to reject.

or

From a PowerCLI command prompt while connected to the vCenter server run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy | Set-VDSecurityPolicy -MacChanges $false
Get-VDPortgroup | Get-VDSecurityPolicy | Set-VDSecurityPolicy -MacChanges $false'
  impact 0.7
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64717r1_chk'
  tag severity: 'high'
  tag gid: 'V-63965'
  tag rid: 'SV-78455r1_rule'
  tag stig_id: 'VCWN-06-000014'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69895r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
