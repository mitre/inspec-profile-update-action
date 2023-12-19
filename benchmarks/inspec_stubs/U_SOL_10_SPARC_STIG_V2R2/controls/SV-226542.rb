control 'SV-226542' do
  title 'All system start-up files must be owned by root.'
  desc 'System start-up files not owned by root could lead to system compromise by allowing malicious users or applications to modify them for unauthorized purposes.  This could lead to system and network compromise.'
  desc 'check', "Check run control scripts' ownership.
# ls -lL /etc/rc* /etc/init.d
If any run control script is not owned by root, this is a finding."
  desc 'fix', 'Change the ownership of the run control script(s) with incorrect ownership.
# chown root <run control script>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28703r483020_chk'
  tag severity: 'medium'
  tag gid: 'V-226542'
  tag rid: 'SV-226542r603265_rule'
  tag stig_id: 'GEN001660'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28691r483021_fix'
  tag 'documentable'
  tag legacy: ['V-4089', 'SV-27207']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
