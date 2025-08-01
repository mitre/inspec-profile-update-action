control 'SV-37384' do
  title 'Cron must not execute group-writable or world-writable programs.'
  desc 'If cron executes group-writable or world-writable programs, there is a possibility that unauthorized users could manipulate the programs with malicious intent.  This could compromise system and network security.'
  desc 'check', 'List all cronjobs on the system. 
Procedure:

# ls /var/spool/cron

# ls /etc/cron.d /etc/crontab /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
or 
# ls /etc/cron*|grep -v deny

If cron jobs exist under any of the above directories, use the following command to search for programs executed by cron:

# more <cron job file>

Perform a long listing of each program file found in the cron file to determine if the file is group-writable or world-writable.

# ls -la <cron program file>

If cron executes group-writable or world-writable files, this is a finding.'
  desc 'fix', 'Remove the world-writable and group-writable permissions from the cron program file(s) identified.
# chmod go-w <cron program file>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36071r1_chk'
  tag severity: 'medium'
  tag gid: 'V-976'
  tag rid: 'SV-37384r1_rule'
  tag stig_id: 'GEN003000'
  tag gtitle: 'GEN003000'
  tag fix_id: 'F-31315r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
