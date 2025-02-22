control 'SV-209038' do
  title 'The sticky bit must be set on all public directories.'
  desc 'Failing to set the sticky bit on public directories allows unauthorized users to delete files in the directory structure. 

The only authorized public directories are those temporary directories supplied with the system, or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system, and by users for temporary file storage - such as /tmp - and for directories requiring global read/write access.'
  desc 'check', 'To find world-writable directories that lack the sticky bit, run the following command for each local partition [PART]: 

# find [PART] -xdev -type d -perm -002 ! -perm -1000

If any world-writable directories are missing the sticky bit, this is a finding.'
  desc 'fix', "When the so-called 'sticky bit' is set on a directory, only the owner of a given file may remove that file from the directory. Without the sticky bit, any user with write access to a directory may remove any file in the directory.

Setting the sticky bit prevents users from removing each other's files. In cases where there is no reason for a directory to be world-writable, a better solution is to remove that permission rather than to set the sticky bit.

However, if a directory is used by a particular application, consult that application's documentation instead of blindly changing modes.
 
To set the sticky bit on a world-writable directory [DIR], run the following command: 

# chmod +t [DIR]"
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9291r357899_chk'
  tag severity: 'low'
  tag gid: 'V-209038'
  tag rid: 'SV-209038r603263_rule'
  tag stig_id: 'OL6-00-000336'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9291r357900_fix'
  tag 'documentable'
  tag legacy: ['SV-65343', 'V-51133']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
