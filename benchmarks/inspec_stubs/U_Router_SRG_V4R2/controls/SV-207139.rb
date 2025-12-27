control 'SV-207139' do
  title 'The PE router must be configured to block any traffic that is destined to IP core infrastructure.'
  desc 'IP/MPLS networks providing VPN and transit services must provide, at the least, the same level of protection against denial-of-service (DoS) attacks and intrusions as Layer 2 networks. Although the IP core network elements are hidden, security should never rely entirely on obscurity.

IP addresses can be guessed. Core network elements must not be accessible from any external host. Protecting the core from any attack is vital for the integrity and privacy of customer traffic as well as the availability of transit services. A compromise of the IP core can result in an outage or, at a minimum, non-optimized forwarding of customer traffic. Protecting the core from an outside attack also prevents attackers from using the core to attack any customer. Hence, it is imperative that all routers at the edge deny traffic destined to any address belonging to the IP core infrastructure.'
  desc 'check', 'Review the router configuration to verify that an ingress ACL is applied to all CE-facing interfaces. 

Verify that the ingress ACL rejects and logs packets destined to the IP core address block. 

If the PE router is not configured to block any traffic with a destination address assigned to the IP core infrastructure, this is a finding.

Note: Internet Control Message Protocol (ICMP) echo requests and traceroutes will be allowed to the edge from external adjacent peers.'
  desc 'fix', 'Configure protection for the IP core to be implemented at the edges by blocking any traffic with a destination address assigned to the IP core infrastructure.'
  impact 0.7
  ref 'DPMS Target Router'
  tag check_id: 'C-7400r382355_chk'
  tag severity: 'high'
  tag gid: 'V-207139'
  tag rid: 'SV-207139r604135_rule'
  tag stig_id: 'SRG-NET-000205-RTR-000007'
  tag gtitle: 'SRG-NET-000205'
  tag fix_id: 'F-7400r382356_fix'
  tag 'documentable'
  tag legacy: ['SV-93019', 'V-78313']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
