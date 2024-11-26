control 'SV-256426' do
  title 'All port groups on standard switches must not be configured to virtual local area network (VLAN) values reserved by upstream physical switches.'
  desc 'Certain physical switches reserve certain VLAN IDs for internal purposes and often disallow traffic configured to these values. For example, Cisco Catalyst switches typically reserve VLANs 1001 to 1024 and 4094, while Nexus switches typically reserve 3968 to 4094. Check the documentation for the specific switch in use. Using a reserved VLAN might result in a denial of service on the network.'
  desc 'check', 'Note: This control addresses ESXi standard switches. Distributed switches are addressed in the vCenter STIG. If there is no standard switch on the ESXi host, this is not applicable.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> Networking >> Virtual switches.

For each standard switch, review the "VLAN ID" on each port group and verify it is not set to a reserved VLAN ID.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VirtualPortGroup -Standard | Select Name, VLanId

If any port group is configured with a reserved VLAN ID, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> Networking >> Virtual switches.

For each port group on a standard switch that is configured to a reserved VLAN, click the "..." button next to the port group.

Click "Edit Settings". On the "Properties" tab, change the "VLAN ID" to a an appropriate VLAN ID and click "OK".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VirtualPortGroup -Name "portgroup name" | Set-VirtualPortGroup -VLanId "New VLAN#"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 ESXi'
  tag check_id: 'C-60101r886057_chk'
  tag severity: 'medium'
  tag gid: 'V-256426'
  tag rid: 'SV-256426r886059_rule'
  tag stig_id: 'ESXI-70-000065'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60044r886058_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
