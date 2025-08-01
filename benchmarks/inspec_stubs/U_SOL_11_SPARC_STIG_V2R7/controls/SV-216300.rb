control 'SV-216300' do
  title 'All run control scripts must have no extended ACLs.'
  desc 'If the startup files are writable by other users, these users could modify the startup files to insert malicious commands into the startup files.'
  desc 'check', 'Verify run control scripts have no extended ACLs.

# ls -lL /etc/rc* /etc/init.d

If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.

# chmod A- [run control script with extended ACL]'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17536r370988_chk'
  tag severity: 'medium'
  tag gid: 'V-216300'
  tag rid: 'SV-216300r603267_rule'
  tag stig_id: 'SOL-11.1-020310'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17534r370989_fix'
  tag 'documentable'
  tag legacy: ['V-59829', 'SV-74259']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
