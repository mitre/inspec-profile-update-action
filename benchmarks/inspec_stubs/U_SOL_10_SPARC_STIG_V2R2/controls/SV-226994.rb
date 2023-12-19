control 'SV-226994' do
  title 'The SSH private host key files must have mode 0600 or less permissive.'
  desc 'If an unauthorized user obtains the private SSH host key file, the host could be impersonated.'
  desc 'check', 'Check the permissions for SSH private host key files.
# ls -lL /etc/ssh/*key
If any file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the permissions for the SSH private host key files.
# chmod 0600 /etc/ssh/*key'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29156r485321_chk'
  tag severity: 'medium'
  tag gid: 'V-226994'
  tag rid: 'SV-226994r603265_rule'
  tag stig_id: 'GEN005523'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29144r485322_fix'
  tag 'documentable'
  tag legacy: ['V-22472', 'SV-26765']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
