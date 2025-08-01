control 'SV-37275' do
  title 'All global initialization files must have mode 0644 or less permissive.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', 'Check global initialization files permissions:


# ls -l /etc/bashrc
# ls -l /etc/csh.cshrc
# ls -l /etc/csh.login
# ls -l /etc/csh.logout
# ls -l /etc/environment
# ls -l /etc/ksh.kshrc
# ls -l /etc/profile
# ls -l /etc/suid_profile
# ls -l /etc/profile.d/*


If global initialization files are more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the global initialization file(s) to 0644.
# chmod 0644 <global initialization file>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35967r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11981'
  tag rid: 'SV-37275r1_rule'
  tag stig_id: 'GEN001720'
  tag gtitle: 'GEN001720'
  tag fix_id: 'F-31223r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
