control 'SV-45102' do
  title 'All global initialization files must not have extended ACLs.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', %q(Check global initialization files for extended ACLs:

# ls -l /etc/bash.bashrc /etc/csh.cshrc /etc/csh.login /etc/environment /etc/ksh.kshrc /etc/profile /etc/profile.d/* /etc/zshrc 2>/dev/null|grep "\+ "

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding.)
  desc 'fix', %q(Remove the extended ACL from the file.

# ls -l /etc/bash.bashrc /etc/csh.cshrc /etc/csh.login /etc/environment /etc/ksh.kshrc /etc/profile /etc/profile.d/* /etc/zshrc 2>/dev/null|grep "\+ "| awk '{ print $8}' xargs setfacl --remove-all)
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42459r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22356'
  tag rid: 'SV-45102r1_rule'
  tag stig_id: 'GEN001730'
  tag gtitle: 'GEN001730'
  tag fix_id: 'F-38501r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
