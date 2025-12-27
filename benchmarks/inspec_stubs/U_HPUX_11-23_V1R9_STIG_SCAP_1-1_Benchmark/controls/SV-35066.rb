control 'SV-35066' do
  title 'The SSH daemon must not permit GSSAPI authentication unless needed.'
  desc 'GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system’s GSSAPI to remote hosts, increasing the attack surface of the system.  GSSAPI authentication must be disabled unless needed.'
  desc 'fix', 'Edit the SSH daemon configuration and delete the keyword entry or modify the entry as follows:

GSSAPIAuthentication no'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'low'
  tag gid: 'V-22473'
  tag rid: 'SV-35066r1_rule'
  tag stig_id: 'GEN005524'
  tag gtitle: 'GEN005524'
  tag fix_id: 'F-30238r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
