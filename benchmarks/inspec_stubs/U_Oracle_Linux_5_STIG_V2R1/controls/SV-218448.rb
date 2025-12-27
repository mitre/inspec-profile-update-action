control 'SV-218448' do
  title 'Cron programs must not set the umask to a value less restrictive than 077.'
  desc 'The umask controls the default access mode assigned to newly created files.  A umask of 077 limits new files to mode 700 or less permissive.  Although umask is often represented as a 4-digit octal number, the first digit representing special access modes is typically ignored or required to be 0.'
  desc 'check', 'Determine if there are any crontabs by viewing a long listing of the directory. If there are crontabs, examine them to determine what cron jobs exist. Check for any programs specifying a umask more permissive than 077:

Procedure:

# ls -lL /var/spool/cron

# ls -lL /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
or
# ls -lL /etc/cron.*|grep -v deny

# cat <crontab file>
# grep umask <cron program>

If there are no cron jobs present, this vulnerability is not applicable. If any cron job contains a umask more permissive than 077, this is a finding.'
  desc 'fix', 'Edit cron script files and modify the umask to 077.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19923r562501_chk'
  tag severity: 'low'
  tag gid: 'V-218448'
  tag rid: 'SV-218448r603259_rule'
  tag stig_id: 'GEN003220'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19921r562502_fix'
  tag 'documentable'
  tag legacy: ['V-4360', 'SV-64337']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
