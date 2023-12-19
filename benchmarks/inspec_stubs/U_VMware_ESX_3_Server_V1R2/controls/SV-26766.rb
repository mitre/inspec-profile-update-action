control 'SV-26766' do
  title 'The SSH daemon must not permit GSSAPI authentication unless needed.'
  desc 'GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system’s GSSAPI to remote hosts, increasing the attack surface of the system.  GSSAPI authentication must be disabled unless needed.'
  desc 'check', "Ask the SA if GSSAPI authentication is used for SSH authentication to the system.  If so, this is not applicable.

Check the SSH daemon configuration for the GSSAPI authentication setting.
# grep -i GSSAPIAuthentication /etc/ssh/sshd_config | grep -v '^#' 
If no lines are returned, or the setting is set to yes, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration and set (add if necessary) a GSSAPIAuthentication directive set to no.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27775r1_chk'
  tag severity: 'low'
  tag gid: 'V-22473'
  tag rid: 'SV-26766r1_rule'
  tag stig_id: 'GEN005524'
  tag gtitle: 'GEN005524'
  tag fix_id: 'F-24016r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
