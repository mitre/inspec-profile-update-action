control 'SV-38803' do
  title 'The system must be configured to use TCP syncookies when experiencing a TCP SYN flood.'
  desc "A TCP SYN flood attack can cause Denial of Service by filling a system's TCP connection table with connections in the SYN_RCVD state.  Syncookies are a mechanism used to not track a connection until a subsequent ACK is received, verifying the initiator is attempting a valid connection and is not a flood source.  This technique does not operate in a fully standards-compliant manner, but is only activated when a flood condition is detected, and allows defense of the system while continuing to service valid requests."
  desc 'check', '# /usr/sbin/no -o clean_partial_conns
If the value returned is not 1,  this is a finding.'
  desc 'fix', '#/usr/sbin/no -p -o clean_partial_conns=1'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37259r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22419'
  tag rid: 'SV-38803r1_rule'
  tag stig_id: 'GEN003612'
  tag gtitle: 'GEN003612'
  tag fix_id: 'F-32500r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001092']
  tag nist: ['SC-5']
end
