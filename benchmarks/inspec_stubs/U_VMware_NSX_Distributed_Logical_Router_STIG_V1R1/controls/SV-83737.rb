control 'SV-83737' do
  title 'The NSX Distributed Logical Router must be configured to disable non-essential capabilities.'
  desc 'A compromised router introduces risk to the entire network infrastructure as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc 'check', 'Verify only necessary services are enabled.

Log onto vSphere Web Client with credentials authorized for administration.

Navigate and select Networking and Security >> select the "NSX Edges" tab on the left-side menu.

Double-click the Edge ID.

Navigate to Manage >> Verify the configurations under "Settings, Firewall, Routing, Bridging, and DHCP Relay" are enabled only as necessary to the deployment.

If unnecessary services are enabled, this is a finding.'
  desc 'fix', 'Log onto vSphere Web Client with credentials authorized for administration.

Navigate and select Networking and Security >> select the "NSX Edges" tab on the left-side menu.

Double-click the Edge ID.

Navigate to Manage >> Verify the configurations under "Settings, Firewall, Routing, Bridging, and DHCP Relay" are enabled only as necessary to the deployment.

If any non-essential services are enabled, select the "disable" option, or remove the configurations under the respective sections.'
  impact 0.5
  ref 'DPMS Target VMware NSX 6 RTR'
  tag check_id: 'C-69571r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69133'
  tag rid: 'SV-83737r1_rule'
  tag stig_id: 'VNSX-RT-000015'
  tag gtitle: 'SRG-NET-000131-RTR-000035'
  tag fix_id: 'F-75319r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
