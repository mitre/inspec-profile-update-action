control 'SV-42274' do
  title 'The system must use an appropriate reverse-path filter for IPv6 network traffic, if the system uses IPv6.'
  desc 'Reverse-path filtering provides protection against spoofed source addresses by causing the system to discard packets with source addresses for which the system has no route or if the route does not point towards the interface on which the packet arrived. Depending on the role of the system, reverse-path filtering may cause legitimate traffic to be discarded and, therefore, should be used with a more permissive mode or filter, or not at all. Whenever possible, reverse-path filtering should be used.'
  desc 'check', 'If IPv6 is not used on the system, this is not applicable.

Determine if the system is configured to use reverse-path filtering.
Examine the IPF rules on the system.
# ipfstat -6i

All systems must block inbound traffic destined to the loopback address block from interfaces other than the loopback. This can be accomplished with an IPF rule such as:

block in log quick on lan0 from 0::1 to any

Additionally, if the system is multihomed and the attached networks are isolated or perform symmetric routing, traffic with source addresses expected on one interface must be blocked when received on another interface.

If this filtering is not configured on the system, this is a finding.'
  desc 'fix', 'Configure the system to use reverse-path filtering using IPF.
Edit /etc/opt/ipf/ipf6.conf to add or edit IPv6 IPF rules.

Add a rule to block traffic with loopback network source addresses from being received on interfaces other than the loopback, such as:

block in log quick on lan0 from 0::1 to any

If the system is multihomed and the attached networks are isolated or perform symmetric routing, add rules to block traffic with source addresses expected on one interface when received on another interface.

For example, consider a system with two network interfaces, one attached to an isolated management network with address 2001:abc::1/64 and the other attached to a production network with address 2001:def::1/64 and a default route. Traffic with a source address on the 2001:abc::0/64 network must be the only traffic accepted on the management interface and must not be accepted on the production interface. This can be accomplished with IPF rules such as:

pass in quick on mgmt0 from 2001:abc::0/64 to any
block in quick on mgmt0 from any to any
block in quick on prod0 from 2001:abc::0/64 to any

Reload the IPF rules.
Flush the rules from your ruleset using the -6Fa option. The -A option specifies the active rules list. The -f option specifies the rules configuration file to be used:

# ipf -6Fa -A -f /etc/opt/ipf/ipf6.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-40620r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22552'
  tag rid: 'SV-42274r1_rule'
  tag stig_id: 'GEN007900'
  tag gtitle: 'GEN007900'
  tag fix_id: 'F-35903r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
