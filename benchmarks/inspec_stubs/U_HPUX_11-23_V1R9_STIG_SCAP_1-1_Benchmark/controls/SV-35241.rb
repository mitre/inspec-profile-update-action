control 'SV-35241' do
  title 'The system must ignore IPv6 Internet Control Message Protocol (ICMP ) redirect messages.'
  desc "ICMP redirect messages are used by routers to inform hosts of a more direct route existing for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack."
  desc 'fix', 'Add an IPF rule to block inbound IPv6 ICMP redirect packets.

Edit /etc/opt/ipf/ipf6.conf and add a rule such as:
block in quick proto icmpv6 from any to any icmpv6-type 137

Reload the IPF rules.
# ipf -6 -Fa -A -f /etc/opt/ipf/ipf6.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22550'
  tag rid: 'SV-35241r1_rule'
  tag stig_id: 'GEN007860'
  tag gtitle: 'GEN007860'
  tag fix_id: 'F-30359r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
