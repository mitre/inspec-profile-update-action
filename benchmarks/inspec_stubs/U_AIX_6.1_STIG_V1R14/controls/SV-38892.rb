control 'SV-38892' do
  title 'All global initialization files must be group-owned by sys, bin, system, or security.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group ownership of global initialization files.

Procedure:
# ls -lL /etc/.login /etc/profile /etc/bashrc /etc/environment /etc/security/environ /etc/security/.profile /etc/csh.login /etc/csh.cshrc

If any global initialization file is not group-owned by sys, bin, system, or security, this is a finding.'
  desc 'fix', 'Change the group ownership of the global initialization file(s) with incorrect group ownership.

Procedure:
# chgrp system <global initialization file>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37162r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11983'
  tag rid: 'SV-38892r1_rule'
  tag stig_id: 'GEN001760'
  tag gtitle: 'GEN001760'
  tag fix_id: 'F-33353r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
