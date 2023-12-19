control 'SV-37279' do
  title 'All global initialization files must not have extended ACLs.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', %q(Check global initialization files for extended ACLs:

# ls -l /etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/csh.logout /etc/environment /etc/ksh.kshrc /etc/profile /etc/suid_profile /etc/profile.d/* 2>null|grep "\+ "

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the file.

# ls -l etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/csh.logout /etc/environment /etc/ksh.kshrc /etc/profile /etc/suid_profile /etc/profile.d/* 2>null|grep "\\+ "|sed "s/^.* \\///g"|xargs setfacl --remove-all'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35970r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22356'
  tag rid: 'SV-37279r1_rule'
  tag stig_id: 'GEN001730'
  tag gtitle: 'GEN001730'
  tag fix_id: 'F-31225r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
