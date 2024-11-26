control 'SV-254060' do
  title 'The Juniper BGP router must be configured to use its loopback address as the source address for iBGP peering sessions.'
  desc 'Using a loopback address as the source address offers a multitude of uses for security, access, management, and scalability of the BGP routers. It is easier to construct appropriate ingress filters for router management plane traffic destined to the network management subnet since the source addresses will be from the range used for loopback interfaces instead of a larger range of addresses used for physical interfaces. Log information recorded by authentication and syslog servers will record the router’s loopback address instead of the numerous physical interface addresses.

When the loopback address is used as the source for eBGP peering, the BGP session will be harder to hijack since the source address to be used is not known globally—making it more difficult for a hacker to spoof an eBGP neighbor. By using traceroute, a hacker can easily determine the addresses for an eBGP speaker when the IP address of an external interface is used as the source address. The routers within the iBGP domain should also use loopback addresses as the source address when establishing BGP sessions.'
  desc 'check', 'Review the router configuration to verify that a loopback address has been configured.

Verify that a loopback interface is used as the source address for all iBGP sessions.
bgp {
    group iBGP {
        type internal;
        local-interface lo0.0;
        :
    }
}

If the router does not use its loopback address as the source address for all iBGP sessions, this is a finding.'
  desc 'fix', 'Ensure that the router’s loopback address is used as the source address when originating traffic.

set protocols bgp group <group name> type internal
set protocols bgp group <group name> local-interface lo0.0'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57512r844211_chk'
  tag severity: 'low'
  tag gid: 'V-254060'
  tag rid: 'SV-254060r844213_rule'
  tag stig_id: 'JUEX-RT-000880'
  tag gtitle: 'SRG-NET-000512-RTR-000001'
  tag fix_id: 'F-57463r844212_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
