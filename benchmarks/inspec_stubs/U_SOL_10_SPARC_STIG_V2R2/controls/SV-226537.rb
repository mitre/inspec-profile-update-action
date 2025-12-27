control 'SV-226537' do
  title 'All run control scripts must have no extended ACLs.'
  desc 'If the startup files are writable by other users, they could modify the startup files to insert malicious commands into the startup files.'
  desc 'check', 'Verify run control scripts have no extended ACLs.
# ls -lL /etc/rc* /etc/init.d
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [run control script with extended ACL]'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28698r483005_chk'
  tag severity: 'medium'
  tag gid: 'V-226537'
  tag rid: 'SV-226537r603265_rule'
  tag stig_id: 'GEN001590'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28686r483006_fix'
  tag 'documentable'
  tag legacy: ['V-22353', 'SV-26460']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
