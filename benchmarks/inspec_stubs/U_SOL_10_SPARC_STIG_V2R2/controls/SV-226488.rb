control 'SV-226488' do
  title 'All network services daemon files must not have extended ACLs.'
  desc 'Restricting permission on daemons will protect them from unauthorized modification and possible system compromise.'
  desc 'check', %q(Verify network services daemon files have no extended ACLs.
# ls -la /usr/sbin
# ls -la /usr/bin
If the permissions include a "+", the file has an extended ACL and this is a finding.
NOTE: Network daemons not residing in these directories (such as httpd or sshd) must also be checked for the correct permissions.

A way to locate network daemons, such as httpd and sshd, is with the ps command.
# ps -ef | egrep '(sshd|httpd)')
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [file with extended ACL]'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28649r482849_chk'
  tag severity: 'medium'
  tag gid: 'V-226488'
  tag rid: 'SV-226488r603265_rule'
  tag stig_id: 'GEN001190'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28637r482850_fix'
  tag 'documentable'
  tag legacy: ['V-22313', 'SV-26361']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
