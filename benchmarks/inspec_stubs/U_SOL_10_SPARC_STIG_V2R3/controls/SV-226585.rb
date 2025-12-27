control 'SV-226585' do
  title 'All public directories must be owned by root or an application account.'
  desc 'If a public directory has the sticky bit set and is not owned by a privileged UID, unauthorized users may be able to modify files created by others.

The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage (e.g., /tmp) and for directories requiring global read/write access.'
  desc 'check', 'Check the ownership of all public directories.

Procedure:
# find / -type d -perm -1002 -exec ls -ld {} \\;

If any public directory is not owned by root or an application user, this is a finding.'
  desc 'fix', 'Change the owner of public directories to root or an application account.

Procedure:
# chown root /tmp

(Replace root with an application user and/or /tmp with another public directory as necessary.)'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28746r483167_chk'
  tag severity: 'medium'
  tag gid: 'V-226585'
  tag rid: 'SV-226585r854421_rule'
  tag stig_id: 'GEN002520'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-28734r483168_fix'
  tag 'documentable'
  tag legacy: ['V-807', 'SV-807']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
