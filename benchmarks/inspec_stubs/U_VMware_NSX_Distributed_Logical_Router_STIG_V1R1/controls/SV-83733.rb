control 'SV-83733' do
  title 'The NSX Distributed Logical Router must enable neighbor router authentication for control plane protocols.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network, or merely used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and Multicast-related protocols.)
  desc 'check', 'Verify for OSPF that Authentication is not set to "None" and for BGP password has been configured.

Log onto vSphere Web Client with credentials authorized for administration.

Navigate and select Networking and Security >> select the "NSX Edges" tab on the left-side menu. 

Double-click the edgeID in question, as denoted by the "Logical Router" type.

Select the "Manage" tab on the top of the new screen >> Routing.

If OSPF is configured, select OSPF >> Area Definitions.

Select the configured areas.

Click the "pencil" icon.

Verify "authentication" is set to something other than "none".

If Authentication is set to "None", this is a finding.

If BGP is configured, select BGP >> Neighbors >> select the configured neighbor >> Click the "pencil" icon >> verify "password" is configured.

If a password has not been configured for BGP, this is a finding.'
  desc 'fix', 'Log onto vSphere Web Client with credentials authorized for administration. 

Navigate and select Networking and Security >> select the "NSX Edges" tab on the left-side menu.

Double-click the edgeID in question, as denoted by the "Logical Router" type.

Select the "Manage" tab on the top of the new screen. >> Routing.

If OSPF is configured, select the "OSPF" option on the left >> select Area Definitions >> select the configured areas.

Click the "pencil" icon.

Select an "authentication" method and configure a value.

If BGP is configured select the "BGP" option on the left.

Select Neighbors >> select the configured neighbor.

Click the "pencil" icon.

Add a password in the "password" section.'
  impact 0.5
  ref 'DPMS Target VMware NSX 6 RTR'
  tag check_id: 'C-69569r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69129'
  tag rid: 'SV-83733r1_rule'
  tag stig_id: 'VNSX-RT-000012'
  tag gtitle: 'SRG-NET-000025-RTR-000020'
  tag fix_id: 'F-75315r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
