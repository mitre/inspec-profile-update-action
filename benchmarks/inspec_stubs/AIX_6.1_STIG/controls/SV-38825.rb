control 'SV-38825' do
  title 'The system must ignore IPv6 ICMP redirect messages.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack."
  desc 'check', 'Determine if the system is configured to ignore IPv6 ICMP redirect messages. If it is not, this is a finding.
# /usr/sbin/no -o ipignoreredirects
If the value returned is not 1, this is a finding.'
  desc 'fix', 'Configure the system to ignore IPv6 ICMP redirect messages.
# /usr/sbin/no -p -o ipignoreredirects=1'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37076r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22550'
  tag rid: 'SV-38825r1_rule'
  tag stig_id: 'GEN007860'
  tag gtitle: 'GEN007860'
  tag fix_id: 'F-32348r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
