control 'SV-40714' do
  title 'The SSH daemon must not permit GSSAPI authentication unless needed.'
  desc 'GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system’s GSSAPI to remote hosts, increasing the attack surface of the system.  GSSAPI authentication must be disabled unless needed.'
  desc 'check', %q(Ask the SA if GSSAPI authentication is used for SSH authentication to the system. If so, this is not applicable.

Check the SSH daemon configuration for the GSSAPI authentication setting.

# grep -i GSSAPIAuthentication /etc/ssh/sshd_config | grep -v '^#'

If the setting is present and set to "yes", this is a finding.  If the setting is absent or set to "no", this is not a finding.)
  desc 'fix', 'Edit /etc/ssh/sshd_config and remove the GSSAPIAuthentication setting or change the value to "no".'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-39444r1_chk'
  tag severity: 'low'
  tag gid: 'V-22473'
  tag rid: 'SV-40714r1_rule'
  tag stig_id: 'GEN005524'
  tag gtitle: 'GEN005524'
  tag fix_id: 'F-34572r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
