control 'SV-216842' do
  title 'The vCenter Server for Windows must not configure all port groups to VLAN values reserved by upstream physical switches.'
  desc 'Certain physical switches reserve certain VLAN IDs for internal purposes and often disallow traffic configured to these values. For example, Cisco Catalyst switches typically reserve VLANs 1001–1024 and 4094, while Nexus switches typically reserve 3968–4047 and 4094. Check with the documentation for your specific switch. Using a reserved VLAN might result in a denial of service on the network.'
  desc 'check', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Policies. 

Review the port group VLAN tags and verify they are not set to a reserved VLAN ID.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:
Get-VDPortgroup | select Name, VlanConfiguration

If any port group is configured with a reserved VLAN ID, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Policies. Click "Edit" and under the VLAN section and change the VLAN ID to an unreserved VLAN ID and click "OK".

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:
Get-VDPortgroup "portgroup name" | Set-VDVlanConfiguration -VlanId "New VLAN#"'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18073r366240_chk'
  tag severity: 'medium'
  tag gid: 'V-216842'
  tag rid: 'SV-216842r612237_rule'
  tag stig_id: 'VCWN-65-000020'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18071r366241_fix'
  tag 'documentable'
  tag legacy: ['SV-104581', 'V-94751']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
