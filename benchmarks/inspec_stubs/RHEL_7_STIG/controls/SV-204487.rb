control 'SV-204487' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that all world-writable directories are group-owned by root, sys, bin, or an application group.'
  desc 'If a world-writable directory is not group-owned by root, sys, bin, or an application Group Identifier (GID), unauthorized users may be able to modify files created by others.

The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.'
  desc 'check', 'The following command will discover and print world-writable directories that are not group-owned by a system account, assuming only system accounts have a GID lower than 1000. Run it once for each local partition [PART]: 

# find [PART] -xdev -type d -perm -0002 -gid +999 -print

If there is output, this is a finding.'
  desc 'fix', 'All directories in local partitions which are world-writable should be group-owned by root or another system account. If any world-writable directories are not group-owned by a system account, this should be investigated. Following this, the directories should be deleted or assigned to an appropriate group.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-36345r602633_chk'
  tag severity: 'medium'
  tag gid: 'V-204487'
  tag rid: 'SV-204487r744106_rule'
  tag stig_id: 'RHEL-07-021030'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-36308r602634_fix'
  tag 'documentable'
  tag legacy: ['V-72047', 'SV-86671']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
