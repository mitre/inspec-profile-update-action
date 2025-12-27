control 'SV-217062' do
  title 'The Juniper BGP router must be configured to use its loopback address as the source address for iBGP peering sessions.'
  desc 'Using a loopback address as the source address offers a multitude of uses for security, access, management, and scalability of the BGP routers. It is easier to construct appropriate ingress filters for router management plane traffic destined to the network management subnet since the source addresses will be from the range used for loopback interfaces instead of a larger range of addresses used for physical interfaces. Log information recorded by authentication and syslog servers will record the router’s loopback address instead of the numerous physical interface addresses.

When the loopback address is used as the source for eBGP peering, the BGP session will be harder to hijack since the source address to be used is not known globally—making it more difficult for a hacker to spoof an eBGP neighbor. By using traceroute, a hacker can easily determine the addresses for an eBGP speaker when the IP address of an external interface is used as the source address. The routers within the iBGP domain should also use loopback addresses as the source address when establishing BGP sessions.'
  desc 'check', 'Review the router configuration to verify that a loopback address has been configured.

interfaces {
    …
    …
    …
    }
    lo0 {
        unit 0 {
            family inet {
                address 2.2.2.2/32;
            }
        }
    }
}

Verify that the loopback interface is used as the source address for all iBGP sessions.

protocols {
    bgp {
        …
        …
        …
        }
group IBGP_PEERS {
    type internal;
    local-address 2.2.2.2;
    neighbor x.x.x.x;
}

If the router does not use its loopback address as the source address for all iBGP sessions, this is a finding.'
  desc 'fix', 'Configure the router to use its loopback address as the source address for all iBGP peering.

[edit protocols bgp group IBGP_PEERS]
set local-address 2.2.2.2'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18291r297054_chk'
  tag severity: 'low'
  tag gid: 'V-217062'
  tag rid: 'SV-217062r604135_rule'
  tag stig_id: 'JUNI-RT-000560'
  tag gtitle: 'SRG-NET-000512-RTR-000001'
  tag fix_id: 'F-18289r297055_fix'
  tag 'documentable'
  tag legacy: ['SV-101117', 'V-90907']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
