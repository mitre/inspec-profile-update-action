control 'SV-78453' do
  title 'The distributed port group Forged Transmits policy must be set to reject.'
  desc 'If the virtual machine operating system changes the MAC address, the operating system can send frames with an impersonated source MAC address at any time. This allows an operating system to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network.

When the Forged transmits option is set to Accept, ESXi does not compare source and effective MAC addresses.

To protect against MAC impersonation, you can set the Forged transmits option to Reject. If you do, the host compares the source MAC address being transmitted by the guest operating system with the effective MAC address for its virtual machine adapter to see if they match. If the addresses do not match, the ESXi host drops the packet.'
  desc 'check', 'From the vSphere Client go to Home >> Networking.

Select a distributed port group and click edit and go to security and verify "Forged Transmits" is set to reject.

or

From a PowerCLI command prompt while connected to the vCenter server run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy

If the "Forged Transmits" policy is set to accept for a non-uplink port, this is a finding.'
  desc 'fix', 'From the vSphere Client go to Home >> Networking.

Select a distributed port group and click edit and go to security and set "Forged Transmits" to reject.

or

From a PowerCLI command prompt while connected to the vCenter server run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy | Set-VDSecurityPolicy -ForgedTransmits $false
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy | Set-VDSecurityPolicy -ForgedTransmits $false'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64715r3_chk'
  tag severity: 'medium'
  tag gid: 'V-63963'
  tag rid: 'SV-78453r2_rule'
  tag stig_id: 'VCWN-06-000013'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69893r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
