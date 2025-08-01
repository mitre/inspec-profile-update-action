control 'SV-207172' do
  title 'The BGP router must be configured to use its loopback address as the source address for iBGP peering sessions.'
  desc 'Using a loopback address as the source address offers a multitude of uses for security, access, management, and scalability of the BGP routers. It is easier to construct appropriate ingress filters for router management plane traffic destined to the network management subnet since the source addresses will be from the range used for loopback interfaces instead of a larger range of addresses used for physical interfaces. Log information recorded by authentication and syslog servers will record the router’s loopback address instead of the numerous physical interface addresses.

When the loopback address is used as the source for eBGP peering, the BGP session will be harder to hijack since the source address to be used is not known globally—making it more difficult for a hacker to spoof an eBGP neighbor. By using traceroute, a hacker can easily determine the addresses for an eBGP speaker when the IP address of an external interface is used as the source address. The routers within the iBGP domain should also use loopback addresses as the source address when establishing BGP sessions.'
  desc 'check', 'Review the router configuration to verify that a loopback address has been configured.

Verify that a loopback interface is used as the source address for all iBGP sessions.

If the router does not use its loopback address as the source address for all iBGP sessions, this is a finding.'
  desc 'fix', 'Ensure that the router’s loopback address is used as the source address when originating traffic.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7433r382604_chk'
  tag severity: 'low'
  tag gid: 'V-207172'
  tag rid: 'SV-207172r604135_rule'
  tag stig_id: 'SRG-NET-000512-RTR-000001'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7433r382605_fix'
  tag 'documentable'
  tag legacy: ['V-78283', 'SV-92989']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
