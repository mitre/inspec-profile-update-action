control 'SV-29719' do
  title 'The system must ignore IPv4 ICMP redirect messages.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack."
  desc 'check', 'Determine if the system is configured to block inbound IPv4 ICMP redirect 
messages.
# ipfstat -i 

Examine the list for a rule such as:
block in quick proto icmp from any to any icmp-type redir

If the listed rules do not block inbound IPv4 ICMP redirect messages, 
this is a finding.'
  desc 'fix', 'Edit /etc/opt/ipf/ipf.conf and add rules to block incoming 
IPv4 ICMP redirect messages, such as:
block in quick proto icmp from any to any icmp-type redir

Reload the IPF rules. Flush the rules from your ruleset using the -Fa option. 
The -A option specifies the active rules list. The -f option specifies the rules
configuration file to be used:

# ipf -Fa -A -f /etc/opt/ipf/ipf.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36510r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22416'
  tag rid: 'SV-29719r1_rule'
  tag stig_id: 'GEN003609'
  tag gtitle: 'GEN003609'
  tag fix_id: 'F-31870r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001503', 'CCI-001551']
  tag nist: ['CM-6 d', 'AC-4']
end
