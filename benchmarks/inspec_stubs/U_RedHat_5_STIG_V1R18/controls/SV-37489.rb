control 'SV-37489' do
  title 'Cron programs must not set the umask to a value less restrictive than 077.'
  desc 'The umask controls the default access mode assigned to newly created files.  A umask of 077 limits new files to mode 700 or less permissive.  Although umask is often represented as a 4-digit octal number, the first digit representing special access modes is typically ignored or required to be 0.'
  desc 'check', 'Determine if there are any crontabs by viewing a long listing of the directory. If there are crontabs, examine them to determine what cron jobs exist. Check for any programs  specifying an umask more permissive than 077:

Procedure:

# ls -lL /var/spool/cron

# ls -lL /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
or 
# ls -lL /etc/cron.*|grep -v deny

# cat <crontab file>
# grep umask <cron program>

If there are no cron jobs present, this vulnerability is not applicable. If any cron job contains an umask more permissive than 077, this is a finding.'
  desc 'fix', 'Edit cron script files and modify the umask to 077.'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36148r1_chk'
  tag severity: 'low'
  tag gid: 'V-4360'
  tag rid: 'SV-37489r1_rule'
  tag stig_id: 'GEN003220'
  tag gtitle: 'GEN003220'
  tag fix_id: 'F-31397r1_fix'
  tag severity_override_guidance: 'If a cron program sets the umask to 000 or does not restrict the world-writable permission, this becomes a CAT I finding.'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
