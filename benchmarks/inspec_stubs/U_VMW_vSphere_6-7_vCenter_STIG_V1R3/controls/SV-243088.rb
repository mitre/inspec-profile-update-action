control 'SV-243088' do
  title 'The vCenter Server must not configure all port groups to VLAN values reserved by upstream physical switches.'
  desc 'Certain physical switches reserve certain VLAN IDs for internal purposes and often disallow traffic configured to these values. For example, Cisco Catalyst switches typically reserve VLANs 1001–1024 and 4094, while Nexus switches typically reserve 3968–4047 and 4094. 

Check with the documentation for the specific switch. Using a reserved VLAN might result in a denial of service on the network.'
  desc 'check', 'If distributed switches are not used, this is not applicable.

From the vSphere Client, go to Networking >> select a distributed switch >> select a distributed port group >> Configure >> Settings >> Policies. 

Review the port group VLAN tags and verify they are not set to a reserved VLAN ID.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-VDPortgroup | select Name, VlanConfiguration

If any port group is configured with a reserved VLAN ID, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Networking >> select a distributed switch >> select a distributed port group >> Configure >> Settings >> Policies. 

Click "Edit".

Under the VLAN section, change the VLAN ID to an unreserved VLAN ID and click "OK".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-VDPortgroup "portgroup name" | Set-VDVlanConfiguration -VlanId "New VLAN#"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46363r816852_chk'
  tag severity: 'medium'
  tag gid: 'V-243088'
  tag rid: 'SV-243088r816854_rule'
  tag stig_id: 'VCTR-67-000020'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46320r816853_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
