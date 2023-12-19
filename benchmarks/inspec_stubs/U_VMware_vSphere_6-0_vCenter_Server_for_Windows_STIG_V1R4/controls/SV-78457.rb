control 'SV-78457' do
  title 'The system must ensure the distributed port group Promiscuous Mode policy is set to reject.'
  desc 'When promiscuous mode is enabled for a virtual switch all virtual machines connected to the Portgroup have the potential of reading all packets across that network, meaning only the virtual machines connected to that Portgroup. Promiscuous mode is disabled by default on the ESXi Server, and this is the recommended setting.'
  desc 'check', 'From the vSphere Client go to Home >> Networking. Select a distributed port group and click edit and go to security and verify "Promiscuous Mode" is set to reject.

or

From a PowerCLI command prompt while connected to the vCenter server run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | Get-VDSecurityPolicy

If the "Promiscuous Mode" policy is set to accept, this is a finding.'
  desc 'fix', 'From the vSphere Client go to Home >> Networking. Select a distributed port group and click edit and go to security and set "Promiscuous Mode" to reject.

or

From a PowerCLI command prompt while connected to the vCenter server run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy | Set-VDSecurityPolicy -AllowPromiscuous $false
Get-VDPortgroup | Get-VDSecurityPolicy | Set-VDSecurityPolicy -AllowPromiscuous $false'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64719r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63967'
  tag rid: 'SV-78457r1_rule'
  tag stig_id: 'VCWN-06-000015'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69897r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
