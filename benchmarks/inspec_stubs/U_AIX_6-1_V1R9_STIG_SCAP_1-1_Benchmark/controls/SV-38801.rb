control 'SV-38801' do
  title 'The system must ignore IPv4 ICMP redirect messages.'
  desc "ICMP redirect messages are used by routers to inform hosts a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack."
  desc 'fix', 'Configure the system to ignore IPv4 ICMP redirect messages. 
#/usr/sbin/no -p -o ipignoreredirects=1'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-22416'
  tag rid: 'SV-38801r1_rule'
  tag stig_id: 'GEN003609'
  tag gtitle: 'GEN003609'
  tag fix_id: 'F-32498r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001503', 'CCI-001551']
  tag nist: ['CM-6 d', 'AC-4']
end
