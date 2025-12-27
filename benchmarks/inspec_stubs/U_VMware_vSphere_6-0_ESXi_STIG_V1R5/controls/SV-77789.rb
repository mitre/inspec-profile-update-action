control 'SV-77789' do
  title 'All port groups must not be configured to VLAN values reserved by upstream physical switches.'
  desc 'Certain physical switches reserve certain VLAN IDs for internal purposes and often disallow traffic configured to these values. For example, Cisco Catalyst switches typically reserve VLANs 1001–1024 and 4094, while Nexus switches typically reserve 3968–4047 and 4094. Check with the documentation for your specific switch. Using a reserved VLAN might result in a denial of service on the network.'
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Networking.  Review the port group VLAN tags and verify they are not set to a reserved VLAN ID.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VirtualPortGroup | Select Name, VLanId

If any port group is configured with a reserved VLAN ID, this is a finding.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Networking >> Select properties on the virtual switch >> Select the port group and click Edit.  Change the VLAN ID to not be a reserved VLAN ID and click OK.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VirtualPortGroup -Name "portgroup name" | Set-VirtualPortGroup -VLanId "New VLAN#"'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64033r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63299'
  tag rid: 'SV-77789r1_rule'
  tag stig_id: 'ESXI-06-000065'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69217r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
