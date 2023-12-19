control 'SV-38268' do
  title 'All global initialization files must be group-owned by root, sys, bin, other system, or the system default.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group ownership of global initialization files.

# ls -lL /etc/profile /etc/bashrc /etc/csh.login /etc/csh.cshrc /etc/.login 

If any global initialization file is not group-owned by root, sys, bin, other, or the system default, this is a finding.'
  desc 'fix', 'Change the group ownership of the global initialization file(s) with incorrect group ownership.

# chgrp root <global initialization file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36378r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11983'
  tag rid: 'SV-38268r1_rule'
  tag stig_id: 'GEN001760'
  tag gtitle: 'GEN001760'
  tag fix_id: 'F-31716r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
