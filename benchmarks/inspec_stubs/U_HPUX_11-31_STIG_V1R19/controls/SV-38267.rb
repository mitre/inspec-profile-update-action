control 'SV-38267' do
  title 'All global initialization files must be owned by bin.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon.  Failure to give ownership of sensitive files or utilities to bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the ownership of global initialization files.

# ls -lL /etc/profile /etc/bashrc /etc/csh.login /etc/csh.cshrc /etc/.login 

If any global initialization file is not owned by bin, this is a finding.'
  desc 'fix', 'Change the ownership of global initialization files with incorrect ownership.

# chown bin <global initialization files>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36377r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11982'
  tag rid: 'SV-38267r1_rule'
  tag stig_id: 'GEN001740'
  tag gtitle: 'GEN001740'
  tag fix_id: 'F-31715r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
