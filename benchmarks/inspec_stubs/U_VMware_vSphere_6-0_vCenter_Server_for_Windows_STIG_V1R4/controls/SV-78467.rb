control 'SV-78467' do
  title 'All port groups must not be configured to VLAN values reserved by upstream physical switches.'
  desc 'Certain physical switches reserve certain VLAN IDs for internal purposes and often disallow traffic configured to these values. For example, Cisco Catalyst switches typically reserve VLANs 1001–1024 and 4094, while Nexus switches typically reserve 3968–4047 and 4094. Check with the documentation for your specific switch. Using a reserved VLAN might result in a denial of service on the network.'
  desc 'check', 'From the vSphere Web Client go to Networking >> Select a distributed port group >> Manage >> Settings >> Policies.  Review the port group VLAN tags and verify they are not set to a reserved VLAN ID.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

Get-VDPortgroup | select Name, VlanConfiguration

If any port group is configured with a reserved VLAN ID, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Networking >> Select a distributed port group >> Manage >> Settings >> Policies.  Click Edit and under the VLAN section change the VLAN ID to not be a reserved VLAN ID and click OK.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

Get-VDPortgroup "portgroup name" | Set-VDVlanConfiguration -VlanId "New VLAN#"'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64729r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63977'
  tag rid: 'SV-78467r1_rule'
  tag stig_id: 'VCWN-06-000020'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69907r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
