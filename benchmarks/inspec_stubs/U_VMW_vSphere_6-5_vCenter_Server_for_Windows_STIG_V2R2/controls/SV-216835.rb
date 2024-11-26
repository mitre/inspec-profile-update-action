control 'SV-216835' do
  title 'The vCenter Server for Windows must set the distributed port group Forged Transmits policy to reject.'
  desc 'If the virtual machine operating system changes the MAC address, the operating system can send frames with an impersonated source MAC address at any time. This allows an operating system to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network.

When the Forged transmits option is set to Accept, ESXi does not compare source and effective MAC addresses.

To protect against MAC impersonation, you can set the Forged transmits option to Reject. If you do, the host compares the source MAC address being transmitted by the guest operating system with the effective MAC address for its virtual machine adapter to see if they match. If the addresses do not match, the ESXi host drops the packet.'
  desc 'check', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Select a port group >> Configure >> Settings >> Policies

Verify "Forged Transmits" is set to reject.

or

From a PowerCLI command prompt while connected to the vCenter server run the following commands:
Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy

If the "Forged Transmits" policy is set to accept for a non-uplink port, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Select a port group >> Configure >> Settings >> Policies >> Edit >> Security. Set "Forged Transmits" to reject. Click "OK".

or

From a PowerCLI command prompt while connected to the vCenter server run the following commands:
Get-VDSwitch | Get-VDSecurityPolicy | Set-VDSecurityPolicy -ForgedTransmits $false
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy | Set-VDSecurityPolicy -ForgedTransmits $false'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18066r366219_chk'
  tag severity: 'medium'
  tag gid: 'V-216835'
  tag rid: 'SV-216835r612237_rule'
  tag stig_id: 'VCWN-65-000013'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18064r366220_fix'
  tag 'documentable'
  tag legacy: ['SV-104567', 'V-94737']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
