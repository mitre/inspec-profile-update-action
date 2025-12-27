control 'SV-243082' do
  title 'The vCenter Server must set the distributed port group Forged Transmits policy to reject.'
  desc 'If the virtual machine operating system changes the MAC address, the operating system can send frames with an impersonated source MAC address at any time. This allows an operating system to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network.

When the Forged transmits option is set to "Accept", ESXi does not compare source and effective MAC addresses.

To protect against MAC impersonation, set the Forged transmits option to "Reject". The host will compare the source MAC address being transmitted by the guest operating system with the effective MAC address for its virtual machine adapter to determine if they match. If the addresses do not match, the ESXi host drops the packet.'
  desc 'check', 'If distributed switches are not used, this is not applicable.

From the vSphere Client, go to Networking >> select a distributed switch >> select a port group >> Configure >> Settings >> Policies.

Verify "Forged Transmits" is set to reject.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy

If the "Forged Transmits" policy is set to accept for a non-uplink port, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Networking >> select a distributed switch >> select a port group >> Configure >> Settings >> Policies >> Edit >> Security. 

Set "Forged Transmits" to reject. Click "OK".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy | Set-VDSecurityPolicy -ForgedTransmits $false
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy | Set-VDSecurityPolicy -ForgedTransmits $false'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46357r816840_chk'
  tag severity: 'medium'
  tag gid: 'V-243082'
  tag rid: 'SV-243082r816841_rule'
  tag stig_id: 'VCTR-67-000013'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46314r719488_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
