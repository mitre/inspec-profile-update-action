control 'SV-218325' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19800r568849_chk'
  tag severity: 'medium'
  tag gid: 'V-218325'
  tag rid: 'SV-218325r603259_rule'
  tag stig_id: 'GEN001720'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19798r568850_fix'
  tag 'documentable'
  tag legacy: ['V-11981', 'SV-63865']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
