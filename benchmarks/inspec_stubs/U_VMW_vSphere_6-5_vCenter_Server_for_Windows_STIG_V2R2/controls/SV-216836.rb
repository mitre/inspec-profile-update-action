control 'SV-216836' do
  title 'The vCenter Server for Windows must set the distributed port group MAC Address Change policy to reject.'
  desc 'If the virtual machine operating system changes the MAC address, it can send frames with an impersonated source MAC address at any time. This allows it to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network. This will prevent VMs from changing their effective MAC address. It will affect applications that require this functionality. This will also affect how a layer 2 bridge will operate. This will also affect applications that require a specific MAC address for licensing.'
  desc 'check', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Select a port group >> Configure >> Settings >> Policies

Verify "MAC Address Changes" is set to reject.

or

From a PowerCLI command prompt while connected to the vCenter server run the following commands:
Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy

If the "MAC Address Changes" policy is set to accept, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Select a port group >> Configure >> Settings >> Policies >> Edit >> Security. Set "MAC Address Changes" to reject. Click "OK".
  
or

From a PowerCLI command prompt while connected to the vCenter server run the following commands:
Get-VDSwitch | Get-VDSecurityPolicy | Set-VDSecurityPolicy -MacChanges $false
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy | Set-VDSecurityPolicy -MacChanges $false'
  impact 0.7
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18067r366222_chk'
  tag severity: 'high'
  tag gid: 'V-216836'
  tag rid: 'SV-216836r612237_rule'
  tag stig_id: 'VCWN-65-000014'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18065r366223_fix'
  tag 'documentable'
  tag legacy: ['SV-104569', 'V-94739']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
