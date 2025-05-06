control 'SV-215190' do
  title 'All AIX public directories must be owned by root or an application account.'
  desc 'If a public directory has the sticky bit set and is not owned by a privileged UID, unauthorized users may be able to modify files created by others. The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.'
  desc 'check', 'Check the ownership of all public directories using command: 
# find / -type d -perm -1002 -exec ls -ld {} \\; 

If any public directory is not owned by "root" or an application user, this is a finding.'
  desc 'fix', 'Use the following command to change the owner to "root" for public directories:
# chown root [public_dir]'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16388r294021_chk'
  tag severity: 'medium'
  tag gid: 'V-215190'
  tag rid: 'SV-215190r508663_rule'
  tag stig_id: 'AIX7-00-001031'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16386r294022_fix'
  tag 'documentable'
  tag legacy: ['V-91589', 'SV-101687']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
