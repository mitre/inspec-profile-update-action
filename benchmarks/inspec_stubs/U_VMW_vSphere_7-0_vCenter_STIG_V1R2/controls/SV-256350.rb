control 'SV-256350' do
  title 'The vCenter Server must set the distributed port group Promiscuous Mode policy to "Reject".'
  desc 'When promiscuous mode is enabled for a virtual switch, all virtual machines connected to the port group have the potential of reading all packets across that network, meaning only the virtual machines connected to that port group.

Promiscuous mode is disabled by default on the ESXi Server, and this is the recommended setting.'
  desc 'check', 'If distributed switches are not used, this is not applicable.

From the vSphere Client, go to "Networking".

Select a distributed switch and then select a port group. 

Select Configure >> Settings >> Policies.

Verify "Promiscuous Mode" is set to "Reject".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy

If the "Promiscuous Mode" policy is set to "Accept", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to "Networking".

Select a distributed switch and then select a port group. 

Select Configure >> Settings >> Policies.

Click "Edit".

Click the "Security" tab.

Set "Promiscuous Mode" to "Reject".

Click "OK".
 
or

From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy | Set-VDSecurityPolicy -AllowPromiscuous $false
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy | Set-VDSecurityPolicy -AllowPromiscuous $false'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 vCenter'
  tag check_id: 'C-60025r885659_chk'
  tag severity: 'medium'
  tag gid: 'V-256350'
  tag rid: 'SV-256350r885661_rule'
  tag stig_id: 'VCSA-70-000270'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-59968r885660_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
