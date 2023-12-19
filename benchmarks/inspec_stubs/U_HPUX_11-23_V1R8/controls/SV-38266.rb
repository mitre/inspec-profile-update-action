control 'SV-38266' do
  title 'All global initialization files must have mode 0444 or less permissive.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', 'Check global initialization files permissions:

# ls -lL /etc/profile /etc/bashrc /etc/csh.login /etc/csh.cshrc /etc/.login 

If global initialization files are more permissive than 0444, this is a finding.'
  desc 'fix', 'Change the mode of the global initialization file(s) to 0444.
# chmod 0444 <global initialization file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36376r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11981'
  tag rid: 'SV-38266r1_rule'
  tag stig_id: 'GEN001720'
  tag gtitle: 'GEN001720'
  tag fix_id: 'F-31714r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
