control 'SV-218326' do
  title 'All global initialization files must not have extended ACLs.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', %q(Check global initialization files for extended ACLs:

# ls -l /etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/csh.logout /etc/environment /etc/ksh.kshrc /etc/profile /etc/suid_profile /etc/profile.d/* 2>null|grep "\+ "

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the file.

# ls -l etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/csh.logout /etc/environment /etc/ksh.kshrc /etc/profile /etc/suid_profile /etc/profile.d/* 2>null|grep "\\+ "|sed "s/^.* \\///g"|xargs setfacl --remove-all'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19801r568852_chk'
  tag severity: 'medium'
  tag gid: 'V-218326'
  tag rid: 'SV-218326r603259_rule'
  tag stig_id: 'GEN001730'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19799r568853_fix'
  tag 'documentable'
  tag legacy: ['V-22356', 'SV-63867']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
