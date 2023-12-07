control 'SV-37285' do
  title 'All global initialization files must be group-owned by root, sys, bin, other, system, or the system default.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'fix', 'Change the group ownership of the global initialization file(s) with incorrect group ownership.

Procedure:
# chgrp root <global initialization file>
or:
# ls -lL /etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/csh.logout /etc/environment /etc/ksh.kshrc /etc/profile /etc/suid_profile /etc/profile.d/* 2>null|sed "s/^[^\\/]*//"|xargs stat -L -c %G:%n|egrep -v "^(root|sys|bin|other):"|cut -d: -f2|xargs chgrp root
will set the group of all files not currently owned by an approved group to root.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-11983'
  tag rid: 'SV-37285r1_rule'
  tag stig_id: 'GEN001760'
  tag gtitle: 'GEN001760'
  tag fix_id: 'F-31232r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
