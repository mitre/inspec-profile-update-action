control 'SV-220033' do
  title 'All global initialization files must be group-owned by root, sys, or bin.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group ownership of global initialization files.

Procedure:
# ls -lL /etc/.login /etc/profile /etc/bashrc /etc/environment /etc/security/environ /etc/csh.login /etc/csh.cshrc

If any global initialization file exists and is not group-owned by root, sys, or bin, this is a finding.'
  desc 'fix', 'Change the group ownership of the global initialization file(s) with incorrect group ownership.

Procedure:
# chgrp root <global initialization file>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21742r483038_chk'
  tag severity: 'medium'
  tag gid: 'V-220033'
  tag rid: 'SV-220033r603265_rule'
  tag stig_id: 'GEN001760'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21741r483039_fix'
  tag 'documentable'
  tag legacy: ['V-11983', 'SV-39831']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
