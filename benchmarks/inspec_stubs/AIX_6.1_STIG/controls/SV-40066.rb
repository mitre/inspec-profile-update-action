control 'SV-40066' do
  title 'All public directories must be group-owned by system or an application group.'
  desc 'If a public directory has the sticky bit set and is not group-owned by a system GID, unauthorized users may be able to modify files created by others.

The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage (e.g., /tmp) and for directories requiring global read/write access.'
  desc 'check', 'Check the group ownership of public directories.

Procedure:
# find / -type d -perm -1002 -exec ls -ld {} \\;

If any public directory is not group-owned by system, sys, bin, or an application group, this is a finding.'
  desc 'fix', 'Change the group ownership of the public directory.

Procedure:
# chgrp system /tmp

(Replace system with a different system group and/or /tmp with a different public directory as necessary.)'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-39055r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11990'
  tag rid: 'SV-40066r1_rule'
  tag stig_id: 'GEN002540'
  tag gtitle: 'GEN002540'
  tag fix_id: 'F-34154r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
