control 'SV-26767' do
  title 'The SSH client must not permit GSSAPI authentication unless needed.'
  desc 'GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system’s GSSAPI to remote hosts, increasing the attack surface of the system.  GSSAPI authentication must be disabled unless needed.'
  desc 'fix', 'Edit the SSH client configuration and set (add if necessary) a  GSSAPIAuthentication directive set to no.'
  impact 0.3
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'low'
  tag gid: 'V-22474'
  tag rid: 'SV-26767r1_rule'
  tag stig_id: 'GEN005525'
  tag gtitle: 'GEN005525'
  tag fix_id: 'F-24017r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
