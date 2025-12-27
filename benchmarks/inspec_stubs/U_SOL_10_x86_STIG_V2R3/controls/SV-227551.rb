control 'SV-227551' do
  title 'The /etc/zones directory, and its contents, must not be group- or world-writable.'
  desc 'Solaris zones configuration files must be protected against illicit creation, modification, and deletion.'
  desc 'check', 'Check the permissions of the files and directories.

# ls -lLdR /etc/zones

If the mode of a directory is more permissive than 0755, or the mode of a file more permissive than 0644, this is a finding.

If zones are not installed on the system, this is not a finding.'
  desc 'fix', 'Change the mode of the file or directory.

# chmod 0644 <file>
For directories:
# chmod 0755 <directory>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29713r488186_chk'
  tag severity: 'medium'
  tag gid: 'V-227551'
  tag rid: 'SV-227551r603266_rule'
  tag stig_id: 'GEN000000-SOL00580'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29701r488187_fix'
  tag 'documentable'
  tag legacy: ['V-22605', 'SV-27019']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
