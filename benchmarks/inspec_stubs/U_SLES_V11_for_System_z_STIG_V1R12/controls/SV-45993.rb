control 'SV-45993' do
  title 'The system must not respond to ICMPv6 echo requests sent to a broadcast address.'
  desc 'Responding to broadcast ICMP echo requests facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', 'Check for an ip6tables rule that drops inbound IPv6 ICMP ECHO_REQUESTs sent to the all-hosts multicast address.

Procedure:
# less /etc/sysconfig/scripts/SuSEfirewall2-custom

Check for a rule in, or referenced by, the INPUT chain such as:
ip6tables -A INPUT -p icmpv6 -d ff02::1 --icmpv6-type 128 -j DROP

If such a rule does not exist, this is a finding.'
  desc 'fix', 'Add an ip6tables rule that drops inbound IPv6 ICMP ECHO_REQUESTs sent to the all-hosts multicast address.

Edit /etc/sysconfig/scripts/SuSEfirewall2-custom and add a rule in, or referenced by, the INPUT chain such as:
ip6tables -A INPUT -p icmpv6 -d ff02::1 --icmpv6-type 128 -j DROP

Reload the SuSEfirewall2 rules.
Procedure:
# rcSuSEfirewall2 restart'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43275r1_chk'
  tag severity: 'medium'
  tag gid: 'V-23972'
  tag rid: 'SV-45993r1_rule'
  tag stig_id: 'GEN007950'
  tag gtitle: 'GEN007950'
  tag fix_id: 'F-39358r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
