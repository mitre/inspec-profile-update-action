control 'SV-38893' do
  title 'Global initialization files must contain the mesg -n or mesg n commands.'
  desc 'If the mesg -n or mesg n command is not placed into the system profile, messaging can be used to cause a Denial of Service attack.'
  desc 'check', 'Check global initialization files for the presence of mesg -n or mesg n.

Procedure:
# grep "mesg" /etc/.login /etc/profile /etc/bashrc /etc/environment /etc/security/environ /etc/security/.profile /etc/csh.login /etc/csh.cshrc

If no global initialization files contain mesg -n or mesg n, this is a finding.'
  desc 'fix', 'Edit /etc/profile or another global initialization script and add the mesg -n command.'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37164r1_chk'
  tag severity: 'low'
  tag gid: 'V-825'
  tag rid: 'SV-38893r1_rule'
  tag stig_id: 'GEN001780'
  tag gtitle: 'GEN001780'
  tag fix_id: 'F-979r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
