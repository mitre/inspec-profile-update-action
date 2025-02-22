control 'SV-255997' do
  title 'The Arista perimeter router must be configured to enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.'
  desc 'Information flow control regulates authorized information to travel within a network and between interconnected networks. Controlling the flow of network traffic is critical so it does not introduce any unacceptable risk to the network infrastructure or data. An example of a flow control restriction is blocking outside traffic claiming to be from within the organization. For most routers, internal information flow control is a product of system design.'
  desc 'check', 'Verify each Arista router enforces approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.

This requirement may be met through the use of IP access control lists. 

Step 1: To verify on the Arista router that IP access lists are configured, execute the "show ip access-lists summary" command and check that the list is configured and is active on applicable interfaces.

router:#show ip access-lists summary
IPV4 ACL $$bgp-ttlSec-ip-vrf-default$$ [dynamic]
        Total rules configured: 1
        Configured on Ingress: bgp(default VRF)
        Active on     Ingress: bgp(default VRF)

IPV4 ACL ACL
        Total rules configured: 1

Standard IPV4 ACL ALLOWED_SOURCES
        Total rules configured: 2

IPV4 ACL AUTHORIZED_SOURCES
        Total rules configured: 3

Step 2: To verify the Arista router lists that control the flow of information in accordance with organizational policy, enter the "show ip access-list [name]" command and review the associated permit and deny statements.

IP Access List ACL.
router#show ip access-list AUTHORIZED_SOURCES
  IP Access List AUTHORIZED_SOURCES
        10 permit ip 10.1.12.0/24 any
        20 deny ip 1.2.3.0/24 any log
        30 deny ip host 10.11.12.2 any log

If the Arista router does not enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy, this is a finding.'
  desc 'fix', 'Configure the router to enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.

To use an IP access list to fulfill this function, enter the following commands, substituting organizational values for the bracketed variables.

ip access-list [name]
[permit/deny] [protocol] [source address] [source port] [destination address] [destination port]
exit

interface [type] [number]
ip access-group [name] [direction]'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59673r882331_chk'
  tag severity: 'medium'
  tag gid: 'V-255997'
  tag rid: 'SV-255997r882333_rule'
  tag stig_id: 'ARST-RT-000110'
  tag gtitle: 'SRG-NET-000019-RTR-000002'
  tag fix_id: 'F-59616r882332_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
