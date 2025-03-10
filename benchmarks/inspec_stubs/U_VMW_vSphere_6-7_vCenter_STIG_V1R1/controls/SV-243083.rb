control 'SV-243083' do
  title 'The vCenter Server must set the distributed port group MAC Address Change policy to reject.'
  desc 'If the virtual machine operating system changes the MAC address, it can send frames with an impersonated source MAC address at any time. This allows it to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network. This will prevent VMs from changing their effective MAC address. It will affect applications that require this functionality. This will also affect how a layer 2 bridge will operate and will affect applications that require a specific MAC address for licensing.'
  desc 'check', 'From the vSphere Client, go to Networking >> select a distributed switch >> select a port group >> Configure >> Settings >> Policies.

Verify "MAC Address Changes" is set to reject.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy

If the "MAC Address Changes" policy is set to accept, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Networking >> select a distributed switch >> select a port group >> Configure >> Settings >> Policies >> Edit >> Security. 

Set "MAC Address Changes" to reject. Click "OK".
 
or

From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy | Set-VDSecurityPolicy -MacChanges $false
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy | Set-VDSecurityPolicy -MacChanges $false'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46358r719490_chk'
  tag severity: 'medium'
  tag gid: 'V-243083'
  tag rid: 'SV-243083r719492_rule'
  tag stig_id: 'VCTR-67-000014'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46315r719491_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
