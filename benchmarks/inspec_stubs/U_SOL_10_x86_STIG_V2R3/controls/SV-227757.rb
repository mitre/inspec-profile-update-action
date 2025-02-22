control 'SV-227757' do
  title 'Cron programs must not set the umask to a value less restrictive than 077.'
  desc 'The umask controls the default access mode assigned to newly created files.  An umask of 077 limits new files to mode 700 or less permissive.  Although umask is often represented as a 4-digit octal number, the first digit representing special access modes is typically ignored or required to be 0.'
  desc 'check', 'Determine if there are any crontabs by viewing a long listing of the directory.  If there are crontabs, examine them to determine what cron jobs exist. Check for any programs specifying  an umask.

# ls -lL /var/spool/cron/crontabs
# cat <crontab file>
# grep umask <cron program>

If there are no cron jobs present, this vulnerability is not applicable.  If any cron job contains an umask value more permissive than 077, this is a finding.

Severity Override Guidance:
If a cron program sets the umask to 000 or does not restrict the world-writable permission, this becomes a CAT I finding.'
  desc 'fix', 'Edit cron script files and modify the umask to 077.'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36464r602995_chk'
  tag severity: 'low'
  tag gid: 'V-227757'
  tag rid: 'SV-227757r854489_rule'
  tag stig_id: 'GEN003220'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-36428r602996_fix'
  tag 'documentable'
  tag legacy: ['V-4360', 'SV-27364']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
