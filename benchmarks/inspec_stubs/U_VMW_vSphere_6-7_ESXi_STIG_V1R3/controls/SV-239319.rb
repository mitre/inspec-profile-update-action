control 'SV-239319' do
  title 'For the ESXi host, all port groups must not be configured to VLAN values reserved by upstream physical switches.'
  desc 'Certain physical switches reserve certain VLAN IDs for internal purposes and often disallow traffic configured to these values. For example, Cisco Catalyst switches typically reserve VLANs 1001-1024 and 4094, while Nexus switches typically reserve 3968-4047 and 4094. Check the documentation for the specific switch. Using a reserved VLAN might result in a denial of service on the network.'
  desc 'check', 'From the vSphere Client, select the ESXi host and go to Configure >> Networking >> Virtual switches. For each virtual switch, review the port group VLAN tags and verify they are not set to a reserved VLAN ID.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VirtualPortGroup | Select Name, VLanId

If any port group is configured with a reserved VLAN ID, this is a finding.'
  desc 'fix', 'From the vSphere Client, select the ESXi host and go to Configure >> Networking >> Virtual switches. 

Highlight a port group where VLAN ID is set to a reserved value and click "Edit" settings (dots). 

Change the VLAN ID to an appropriate VLAN and click "OK".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VirtualPortGroup -Name "portgroup name" | Set-VirtualPortGroup -VLanId "New VLAN#"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 ESXi'
  tag check_id: 'C-42552r674884_chk'
  tag severity: 'medium'
  tag gid: 'V-239319'
  tag rid: 'SV-239319r674886_rule'
  tag stig_id: 'ESXI-67-000065'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-42511r674885_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
