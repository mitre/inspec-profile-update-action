control 'SV-218373' do
  title 'All public directories must be group-owned by root, sys, bin, or an application group.'
  desc 'If a public directory has the sticky bit set and is not group-owned by a privileged GID, unauthorized users may be able to modify files created by others.

The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.'
  desc 'check', 'Check the group-ownership of public directories.

Procedure:
# find / -type d -perm -1002 -exec ls -ld {} \\;

If any public directory is not group-owned by root, sys, bin, or an application group, this is a finding.'
  desc 'fix', 'Change the group-ownership of the public directory.

Procedure:
# chgrp root /tmp

(Replace root with a different system group and/or /tmp with a different public directory as necessary.)'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19848r569077_chk'
  tag severity: 'medium'
  tag gid: 'V-218373'
  tag rid: 'SV-218373r603259_rule'
  tag stig_id: 'GEN002540'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-19846r569078_fix'
  tag 'documentable'
  tag legacy: ['V-11990', 'SV-63797']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
