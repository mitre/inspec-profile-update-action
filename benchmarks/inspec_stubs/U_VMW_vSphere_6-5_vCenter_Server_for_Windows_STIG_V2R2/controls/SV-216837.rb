control 'SV-216837' do
  title 'The vCenter Server for Windows must set the distributed port group Promiscuous Mode policy to reject.'
  desc 'When promiscuous mode is enabled for a virtual switch all virtual machines connected to the Portgroup have the potential of reading all packets across that network, meaning only the virtual machines connected to that Portgroup. Promiscuous mode is disabled by default on the ESXi Server, and this is the recommended setting.'
  desc 'check', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Select a port group >> Configure >> Settings >> Policies

Verify "Promiscuous Mode" is set to reject.

or

From a PowerCLI command prompt while connected to the vCenter server run the following commands:
Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy

If the "Promiscuous Mode" policy is set to accept, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Select a port group >> Configure >> Settings >> Policies >> Edit >> Security. Set "Promiscuous Mode" to reject. Click "OK".
  
or

From a PowerCLI command prompt while connected to the vCenter server run the following commands:
Get-VDSwitch | Get-VDSecurityPolicy | Set-VDSecurityPolicy -AllowPromiscuous $false
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy | Set-VDSecurityPolicy -AllowPromiscuous $false'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18068r366225_chk'
  tag severity: 'medium'
  tag gid: 'V-216837'
  tag rid: 'SV-216837r612237_rule'
  tag stig_id: 'VCWN-65-000015'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18066r366226_fix'
  tag 'documentable'
  tag legacy: ['SV-104571', 'V-94741']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
