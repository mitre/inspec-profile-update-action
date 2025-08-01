control 'SV-218689' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20164r556484_chk'
  tag severity: 'medium'
  tag gid: 'V-218689'
  tag rid: 'SV-218689r603259_rule'
  tag stig_id: 'GEN007950'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20162r556485_fix'
  tag 'documentable'
  tag legacy: ['V-23972', 'SV-63385']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
