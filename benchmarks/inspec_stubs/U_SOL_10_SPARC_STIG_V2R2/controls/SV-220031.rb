control 'SV-220031' do
  title 'All global initialization files must have mode 0644 or less permissive.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', 'Check global initialization files permissions.

# ls -l /etc/.login
# ls -l /etc/profile
# ls -l /etc/bashrc
# ls -l /etc/environment
# ls -l /etc/security/environ
# ls -l /etc/csh.login 
# ls -l /etc/csh.cshrc

If global initialization files exist and are more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the global initialization file(s) to 0644.
# chmod 0644 <global initialization file>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21740r483029_chk'
  tag severity: 'medium'
  tag gid: 'V-220031'
  tag rid: 'SV-220031r603265_rule'
  tag stig_id: 'GEN001720'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21739r483030_fix'
  tag 'documentable'
  tag legacy: ['V-11981', 'SV-39829']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
