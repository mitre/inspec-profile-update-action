control 'SV-45105' do
  title 'All global initialization files must be group-owned by root, sys, bin, other, system, or the system default.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group ownership of global initialization files.

Procedure:
# ls -lL /etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/environment /etc/ksh.kshrc /etc/profile /etc/profile.d/* /etc/zshrc

This should show information for each file. Examine to ensure the group is always root

or:
# ls -lL /etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/environment /etc/ksh.kshrc /etc/profile /etc/profile.d/* /etc/zshrc 2>/dev/null|sed "s/^[^\\/]*//"|xargs stat -L -c %G:%n|egrep -v "^(root|sys|bin|other):"
will show you only the group and filename of files not owned by one of the approved groups.

If any global initialization file is not group-owned by root, sys, bin, other, system, or the system default, this is a finding.'
  desc 'fix', 'Change the group ownership of the global initialization file(s) with incorrect group ownership.

Procedure:
# chgrp root <global initialization file>
or:
# ls -lL /etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/environment /etc/ksh.kshrc /etc/profile /etc/profile.d/* /etc/zshrc 2>/dev/null|sed "s/^[^\\/]*//"|xargs stat -L -c %G:%n|egrep -v "^(root|sys|bin|other):"|cut -d: -f2|xargs chgrp root
will set the group of all files not currently owned by an approved group to root.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42462r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11983'
  tag rid: 'SV-45105r1_rule'
  tag stig_id: 'GEN001760'
  tag gtitle: 'GEN001760'
  tag fix_id: 'F-38504r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
