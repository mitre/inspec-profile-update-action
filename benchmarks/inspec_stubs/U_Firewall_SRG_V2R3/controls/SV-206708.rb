control 'SV-206708' do
  title 'The firewall must restrict traffic entering the VPN tunnels to the management network to only the authorized management packets based on destination address.'
  desc 'Protect the management network with a filtering firewall configured to block unauthorized traffic. This requirement is similar to the out-of-band management (OOBM) model, when the production network is managed in-band. The management network could also be housed at a Network Operations Center (NOC) that is located locally or remotely at a single or multiple interconnected sites. 

NOC interconnectivity, as well as connectivity between the NOC and the managed networks’ premise routers, would be enabled using either provisioned circuits or VPN technologies such as IPsec tunnels or MPLS VPN services.'
  desc 'check', 'Inspect the architecture diagrams. Inspect the NOC and the managed network. Note that the IPsec tunnel endpoints may be configured on the premise or gateway router, the VPN gateway firewall, or a VPN concentrator. 

Verify that all traffic between the managed network and management network and vice-versa is secured via IPsec encapsulation.

If the firewall does not restrict traffic entering the VPN tunnels to the management network to only the authorized management packets based on destination address, this is a finding.'
  desc 'fix', 'Where IPsec technology is deployed to connect the managed network to the NOC, restrict the traffic entering the tunnels so that only the authorized management packets with authorized destination addresses are permitted.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6965r297903_chk'
  tag severity: 'medium'
  tag gid: 'V-206708'
  tag rid: 'SV-206708r855868_rule'
  tag stig_id: 'SRG-NET-000364-FW-000036'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-6965r297904_fix'
  tag 'documentable'
  tag legacy: ['SV-94185', 'V-79479']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
