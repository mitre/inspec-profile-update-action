control 'SV-45202' do
  title 'The sticky bit must be set on all public directories.'
  desc 'Failing to set the sticky bit on the public directories allows unauthorized users to delete files in the directory structure.

The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.'
  desc 'check', 'Check all world-writable directories have the sticky bit set.

Procedure:
# find / -type d -perm -002 ! -perm -1000 > wwlist

If the sticky bit is not set on a world-writable directory, this is a finding.'
  desc 'fix', 'Set the sticky bit on all public directories.

Procedure:
# chmod 1777 /tmp

(Replace /tmp with the public directory missing the sticky bit, if necessary.'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42550r1_chk'
  tag severity: 'low'
  tag gid: 'V-806'
  tag rid: 'SV-45202r1_rule'
  tag stig_id: 'GEN002500'
  tag gtitle: 'GEN002500'
  tag fix_id: 'F-38598r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
