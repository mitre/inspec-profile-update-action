control 'SV-38964' do
  title 'The system must use an appropriate reverse-path filter for IPv6 network traffic, if the system uses IPv6.'
  desc 'Reverse-path filtering provides protection against spoofed source addresses by causing the system to discard packets that have source addresses for which the system has no route or if the route does not point towards the interface on which the packet arrived. Depending on the role of the system, reverse-path filtering may cause legitimate traffic to be discarded and, therefore, should be used with a more permissive mode or filter, or not at all. Whenever possible, reverse-path filtering should be used.'
  desc 'check', 'Determine if the system is configured to use reverse-path filtering. 
Examine the IPSec rules on the system.
# lsfilt -a
All systems must block inbound traffic destined to the loopback address from other network interfaces. 

Additionally, if the system is multihomed and the attached networks are isolated or perform symmetric routing, traffic with source addresses expected on one interface must be blocked when received on another interface.

If filtering is not configured on the system, this is a finding.'
  desc 'fix', 'Configure the system to use reverse-path filtering using IP Sec filters. 

Add rules to block traffic with loopback network source addresses from being received on interfaces other than the loopback, such as other ethernet interfaces.

Use smitty or genfilt command to block loopback address from network interfaces.
# smitty ipsec6
# genfilt -v6 -a D -s <source address> -m <source netmask> -d <destination address>  -M <Destination mask> -c all -o any -O any  -p 0 -P 0 -w I -l y -a en0

If the system is multihomed and the attached networks are isolated or perform symmetric routing, add rules to block traffic with source addresses expected on one interface when received on another interface.

# smitty ipsec6'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37917r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22552'
  tag rid: 'SV-38964r1_rule'
  tag stig_id: 'GEN007900'
  tag gtitle: 'GEN007900'
  tag fix_id: 'F-33173r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
