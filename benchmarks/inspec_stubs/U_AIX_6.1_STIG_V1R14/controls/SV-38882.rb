control 'SV-38882' do
  title 'All global initialization files must have mode 0644 or less permissive.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', 'Check global initialization files permissions:

# ls -l /etc/.login /etc/profile /etc/bashrc /etc/environment /etc/security/environ /etc/security/.profile /etc/csh.login /etc/csh.cshrc

If global initialization files are more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the global initialization file(s) to 0444.
# chmod 0444 <global initialization file>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37157r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11981'
  tag rid: 'SV-38882r1_rule'
  tag stig_id: 'GEN001720'
  tag gtitle: 'GEN001720'
  tag fix_id: 'F-11242r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
