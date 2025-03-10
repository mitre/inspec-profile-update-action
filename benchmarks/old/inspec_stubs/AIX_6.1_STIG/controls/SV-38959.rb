control 'SV-38959' do
  title 'The system must use an access control program.'
  desc 'Access control programs (such as TCP_WRAPPERS) provide the ability to enhance system security posture.'
  desc 'check', 'Determine if TCP_WRAPPERS is being used.
# grep tcpd /etc/inetd.conf
If no services are listed, this is a finding.'
  desc 'fix', 'Edit /etc/inetd.conf and use tcpd to wrap services.   
Use SMIT to install TCP Wrappers from the AIX Expansion pack media as fileset netsec.options.tcpwrappers.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28781r1_chk'
  tag severity: 'medium'
  tag gid: 'V-940'
  tag rid: 'SV-38959r1_rule'
  tag stig_id: 'GEN006580'
  tag gtitle: 'GEN006580'
  tag fix_id: 'F-32344r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'EBRU-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
