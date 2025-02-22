control 'SV-220032' do
  title 'All global initialization files must be owned by root.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the ownership of global initialization files. 
Procedure: 
# ls -lL /etc/.login /etc/profile /etc/bashrc /etc/environment /etc/security/environ /etc/csh.login /etc/csh.cshrc

If any global initialization file exists and is not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of global initialization files with incorrect ownership.

Procedure:
# chown bin <global initialization files>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21741r483035_chk'
  tag severity: 'medium'
  tag gid: 'V-220032'
  tag rid: 'SV-220032r603265_rule'
  tag stig_id: 'GEN001740'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21740r483036_fix'
  tag 'documentable'
  tag legacy: ['V-11982', 'SV-39830']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
