control 'SV-218328' do
  title 'All global initialization files must be group-owned by root, sys, bin, other, system, or the system default.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group ownership of global initialization files.

Procedure:
# ls -lL etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/csh.logout /etc/environment /etc/ksh.kshrc /etc/profile /etc/suid_profile /etc/profile.d/* 

This should show information for each file. Examine to ensure the group is always root

or:
# ls -lL etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/csh.logout /etc/environment /etc/ksh.kshrc /etc/profile /etc/suid_profile /etc/profile.d/* 2>null|sed "s/^[^\\/]*//"|xargs stat -L -c %G:%n|egrep -v "^(root|sys|bin|other):"
will show you only the group and filename of files not owned by one of the approved groups.

If any global initialization file is not group-owned by root, sys, bin, other, system, or the system default, this is a finding.'
  desc 'fix', 'Change the group ownership of the global initialization file(s) with incorrect group ownership.

Procedure:
# chgrp root <global initialization file>
or:
# ls -lL /etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/csh.logout /etc/environment /etc/ksh.kshrc /etc/profile /etc/suid_profile /etc/profile.d/* 2>null|sed "s/^[^\\/]*//"|xargs stat -L -c %G:%n|egrep -v "^(root|sys|bin|other):"|cut -d: -f2|xargs chgrp root
will set the group of all files not currently owned by an approved group to root.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19803r568858_chk'
  tag severity: 'medium'
  tag gid: 'V-218328'
  tag rid: 'SV-218328r603259_rule'
  tag stig_id: 'GEN001760'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19801r568859_fix'
  tag 'documentable'
  tag legacy: ['V-11983', 'SV-63871']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
