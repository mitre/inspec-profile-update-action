control 'SV-243084' do
  title 'The vCenter Server must set the distributed port group Promiscuous Mode policy to reject.'
  desc 'When promiscuous mode is enabled for a virtual switch, all virtual machines connected to the port group have the potential of reading all packets across that network, meaning only the virtual machines connected to that port group. Promiscuous mode is disabled by default on the ESXi Server, and this is the recommended setting.'
  desc 'check', 'From the vSphere Client, go to Networking >> select a distributed switch >> select a port group >> Configure >> Settings >> Policies.

Verify "Promiscuous Mode" is set to reject.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy

If the "Promiscuous Mode" policy is set to accept, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Networking >> select a distributed switch >> select a port group >> Configure >> Settings >> Policies >> Edit >> Security. 

Set "Promiscuous Mode" to reject. Click "OK".
 
or

From a PowerCLI command prompt while connected to the vCenter server, run the following commands:


Get-VDSwitch | Get-VDSecurityPolicy | Set-VDSecurityPolicy -AllowPromiscuous $false
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy | Set-VDSecurityPolicy -AllowPromiscuous $false'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46359r719493_chk'
  tag severity: 'medium'
  tag gid: 'V-243084'
  tag rid: 'SV-243084r719495_rule'
  tag stig_id: 'VCTR-67-000015'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46316r719494_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
