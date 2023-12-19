control 'SV-34950' do
  title 'All public directories must be owned by root or an application account.'
  desc 'If a public directory has the sticky bit set and is not owned by a privileged UID, unauthorized users may be able to modify files created by others.

The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage (e.g., /tmp) and for directories requiring global read/write access.'
  desc 'check', 'Check the ownership of all public directories.

Procedure:
# find / -type d -perm -1002 -exec ls -ld {} \\;

If any public directory is not owned by root or an application user, this is a finding.'
  desc 'fix', 'Change the owner of public directories to root or an application account.

Procedure:
# chown root <public directory>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36406r1_chk'
  tag severity: 'medium'
  tag gid: 'V-807'
  tag rid: 'SV-34950r1_rule'
  tag stig_id: 'GEN002520'
  tag gtitle: 'GEN002520'
  tag fix_id: 'F-31744r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
