control 'SV-37866' do
  title 'The SSH daemon must not permit GSSAPI authentication unless needed.'
  desc "GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system's GSSAPI to remote hosts, increasing the attack surface of the system.  GSSAPI authentication must be disabled unless needed."
  desc 'fix', 'Edit the SSH daemon configuration and set (add if necessary) a "GSSAPIAuthentication" directive set to "no".

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag severity: 'low'
  tag gid: 'V-22473'
  tag rid: 'SV-37866r3_rule'
  tag stig_id: 'GEN005524'
  tag gtitle: 'GEN005524'
  tag fix_id: 'F-32342r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
