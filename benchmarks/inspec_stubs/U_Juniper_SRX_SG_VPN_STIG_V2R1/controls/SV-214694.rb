control 'SV-214694' do
  title 'The Juniper SRX Services Gateway VPN must only allow incoming VPN communications from organization-defined authorized sources routed to organization-defined authorized destinations.'
  desc 'Unrestricted traffic may contain malicious traffic which poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Access control policies and access control lists implemented on devices, such as firewalls, that control the flow of network traffic, ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the Internet) must be kept separated.'
  desc 'check', 'Request documentation of the Juniper SRX configuration drawings to determine which ports are configured for external/outbound traffic. Verify outbound interfaces have been configured with DoS screens.

[edit]
show security zones <security-zone-name>

If the VPN zone(s) is configured to allow unauthorized/untrusted traffic to unauthorized zones, this is a finding.'
  desc 'fix', 'The SRX device will route traffic over the IPsec VPN’s secure tunnel interface if there is a route with the next-hop specified as the secure tunnel interface. The following example commands configure an IPv4 and IPv6 static route for their respective secure tunnels.

set routing-options static route <IPv4 network/netmask> next-hop st0.0
set routing-options rib inet6.0 static route <IPv6 network/mask> next-hop st0.1
set security policies from-zone untrust to-zone trust policy group-sec-policy then permit tunnel ipsec-vpn groupvpn

Note: For the SRX device to transmit traffic over the IPsec tunnel, you must configure the secure tunnel interface (st0 in this case), associate it with a security zone, and create a static route entry for the remote network’s address space.'
  impact 0.5
  ref 'DPMS Target Juniper SRX Services Gateway VPN'
  tag check_id: 'C-15895r297669_chk'
  tag severity: 'medium'
  tag gid: 'V-214694'
  tag rid: 'SV-214694r383581_rule'
  tag stig_id: 'JUSX-VN-000027'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-15893r297670_fix'
  tag 'documentable'
  tag legacy: ['SV-81165', 'V-66675']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
