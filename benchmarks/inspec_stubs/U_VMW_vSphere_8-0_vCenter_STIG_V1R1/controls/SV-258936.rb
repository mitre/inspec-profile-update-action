control 'SV-258936' do
  title 'The vCenter Server must set the distributed port group Media Access Control (MAC) Address Change policy to "Reject".'
  desc 'If the virtual machine operating system changes the MAC address, it can send frames with an impersonated source MAC address at any time. This allows it to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network.

This will prevent virtual machines from changing their effective MAC address and will affect applications that require this functionality. This will also affect how a layer 2 bridge will operate and will affect applications that require a specific MAC address for licensing.'
  desc 'check', 'If distributed switches are not used, this is not applicable.

From the vSphere Client, go to "Networking".

Select a distributed switch >> Select a port group >> Configure >> Settings >> Policies.

Verify "MAC Address Changes" is set to "Reject".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy

If the "MAC Address Changes" policy is set to accept, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to "Networking".

Select a distributed switch >> Select a port group >> Configure >> Settings >> Policies.

Click "Edit".

Click the "Security" tab.

Set "MAC Address Changes" to "Reject".

Click "OK".
 
or

From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy | Set-VDSecurityPolicy -MacChanges $false
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy | Set-VDSecurityPolicy -MacChanges $false'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 vCenter'
  tag check_id: 'C-62676r934464_chk'
  tag severity: 'medium'
  tag gid: 'V-258936'
  tag rid: 'SV-258936r934466_rule'
  tag stig_id: 'VCSA-80-000269'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-62585r934465_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
