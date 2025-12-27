control 'SV-29788' do
  title 'The system must not respond to ICMPv6 echo requests sent to a broadcast address.'
  desc 'Responding to broadcast ICMP echo requests facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', 'Check for an iptables rule that drops inbound IPv6 ICMP ECHO_REQUESTs sent to the all-hosts multicast address.

Procedure:
# less /etc/sysconfig/ip6tables

Check for a rule in, or referenced by, the INPUT chain such as:
-A INPUT -p icmpv6 -d ff02::1 --icmpv6-type 128 -j DROP

If such a rule does not exist, this is a finding.'
  desc 'fix', 'Add an iptables rule that drops inbound IPv6 ICMP ECHO_REQUESTs sent to the all-hosts multicast address.

Edit /etc/sysconfig/ip6tables and add a rule in, or referenced by, the INPUT chain such as:
-A INPUT -p icmpv6 -d ff02::1 --icmpv6-type 128 -j DROP

Reload the iptables rules.
Procedure:
# service ip6tables restart'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-30069r1_chk'
  tag severity: 'medium'
  tag gid: 'V-23972'
  tag rid: 'SV-29788r1_rule'
  tag stig_id: 'GEN007950'
  tag gtitle: 'GEN007950'
  tag fix_id: 'F-26899r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
