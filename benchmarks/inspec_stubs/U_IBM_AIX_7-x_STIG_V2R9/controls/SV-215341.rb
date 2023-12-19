control 'SV-215341' do
  title 'The sticky bit must be set on all public directories on AIX systems.'
  desc 'Failing to set the sticky bit on public directories allows unauthorized users to delete files in the directory structure. The only authorized public directories are those temporary directories supplied with the system, or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system, and by users for temporary file storage - such as /tmp - and for directories requiring global read/write access.'
  desc 'check', 'Verify all world-writable directories have the sticky bit set by running the command: 

# find / -type d -perm -002 ! -perm -1000 > wwlist 
# cat wwlist

If any directories are listed in the "wwlist" file, this is a finding.'
  desc 'fix', 'Set the sticky bit on all public directories, such as: 
# chmod 1777 /tmp 

(Replace /tmp with the public directory missing the sticky bit, if necessary.)'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16539r294474_chk'
  tag severity: 'medium'
  tag gid: 'V-215341'
  tag rid: 'SV-215341r508663_rule'
  tag stig_id: 'AIX7-00-003035'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16537r294475_fix'
  tag 'documentable'
  tag legacy: ['V-91629', 'SV-101727']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
