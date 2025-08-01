control 'SV-38265' do
  title 'All public directories must be group-owned by root or an application group.'
  desc 'If a public directory has the sticky bit set and is not group-owned by a privileged GID, unauthorized users may be able to modify files created by others.

The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage (e.g., /tmp) and for directories requiring global read/write access.'
  desc 'check', 'Check the group-ownership of public directories.

Procedure:
# find / -type d -perm -1002 -exec ls -ld {} \\;

If any public directory is not group-owned by root, sys, bin, other or an application group, this is a finding.'
  desc 'fix', 'Change the group-ownership of the public directory.

Procedure:
# chgrp root <public directory>

(Replace root with a different system group as necessary.)'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36423r2_chk'
  tag severity: 'medium'
  tag gid: 'V-11990'
  tag rid: 'SV-38265r1_rule'
  tag stig_id: 'GEN002540'
  tag gtitle: 'GEN002540'
  tag fix_id: 'F-31762r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
