control 'SV-256040' do
  title 'The Arista perimeter router must be configured to only allow incoming communications from authorized sources to be routed to authorized destinations.'
  desc "Unrestricted traffic may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Traffic can be restricted directly by an access control list (ACL), which is a firewall function, or by Policy Routing. Policy Routing is a technique used to make routing decisions based on a number of different criteria other than just the destination network, including source or destination network, source or destination address, source or destination port, protocol, packet size, and packet classification. This overrides the router's normal routing procedures used to control the specific paths of network traffic. It is normally used for traffic engineering but can also be used to meet security requirements; for example, traffic that is not allowed can be routed to the Null0 or discard interface. Policy Routing can also be used to control which prefixes appear in the routing table.

This requirement is intended to allow network administrators the flexibility to use whatever technique is most effective."
  desc 'check', 'This requirement is not applicable for the DODIN backbone.

Review the Arista router configuration to determine if the router allows only incoming communications from authorized sources to be routed to authorized destinations.

Step 1: Verify the ACL is defined as in the following example.

Execute the command "sh ip access-list".

ip access-list AUTHORIZED_SOURCES
 permit ip 10.1.12.0/24 any
 deny ip 1.2.3.0/24 any log

Step 2: Verify the ACL is applied inbound on the external interface.

interface ethernet 3
 ip access-group AUTHORIZED_SOURCES in

If the Arista router does not restrict incoming communications to allow only authorized sources and destinations, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone.

Configure the Arista router to allow only incoming communications from authorized sources to be routed to authorized destinations, such as the example shown below.

LEAF-1A(config-acl-AUTHORIZED_SOURCES)# permit ip 10.1.12.0/24 any
LEAF-1A(config-acl-AUTHORIZED_SOURCES)# deny ip 1.2.3.0/24 any log
LEAF-1A(config-acl-AUTHORIZED_SOURCES)#exit

LEAF-1A(config)#interface ethernet 3
LEAF-1A(config-if-Et3)# ip access-group AUTHORIZED_SOURCES in'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59716r882460_chk'
  tag severity: 'medium'
  tag gid: 'V-256040'
  tag rid: 'SV-256040r882462_rule'
  tag stig_id: 'ARST-RT-000610'
  tag gtitle: 'SRG-NET-000364-RTR-000109'
  tag fix_id: 'F-59659r882461_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
