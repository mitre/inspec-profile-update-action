control 'SV-29786' do
  title 'The system must not respond to ICMPv6 echo requests sent to a broadcast address.'
  desc 'Responding to broadcast ICMP echo requests facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', 'Determine if the system blocks inbound IPv6 ICMP echo-requests sent to the all-hosts multicast address.

Procedure:
# ipfstat -6 -i

Check for a rule such as:
block in quick proto icmpv6 from any to ff02::1 icmpv6-type 128

If a rule blocking inbound IPv6 ICMP echo-requests sent to the all-hosts multicast address does not exist, this is a finding.'
  desc 'fix', 'Add an IPF rule to block inbound IPv6 ICMP ECHO_REQUEST packets sent to the all-hosts multicast address.

Edit /etc/opt/ipf/ipf6.conf and add a rule such as:
block in quick proto icmpv6 from any to ff02::1 icmpv6-type 128

Reload the IPF rules.
# ipf -6 -Fa -A -f /etc/opt/ipf/ipf6.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36757r1_chk'
  tag severity: 'medium'
  tag gid: 'V-23972'
  tag rid: 'SV-29786r1_rule'
  tag stig_id: 'GEN007950'
  tag gtitle: 'GEN007950'
  tag fix_id: 'F-32141r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
