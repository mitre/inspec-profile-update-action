control 'SV-226584' do
  title 'The sticky bit must be set on all public directories.'
  desc 'Failing to set the sticky bit on the public directories allows unauthorized users to delete files in the directory structure.

The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage (e.g., /tmp) and for directories requiring global read/write access.'
  desc 'check', 'Verify all world-writable directories have the sticky bit set.

Procedure:
# find / -type d -perm -002 ! -perm -1000 > wwlist

If the sticky bit is not set on a world-writable directory, this is a finding.'
  desc 'fix', 'Set the sticky bit on all public directories.  

Procedure:
# chmod 1777 /tmp

(Replace /tmp with the public directory missing the sticky bit, if necessary.)'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28745r483164_chk'
  tag severity: 'low'
  tag gid: 'V-226584'
  tag rid: 'SV-226584r603265_rule'
  tag stig_id: 'GEN002500'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28733r483165_fix'
  tag 'documentable'
  tag legacy: ['V-806', 'SV-806']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
