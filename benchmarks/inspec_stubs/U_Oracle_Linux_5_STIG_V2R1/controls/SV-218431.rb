control 'SV-218431' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19906r562453_chk'
  tag severity: 'medium'
  tag gid: 'V-218431'
  tag rid: 'SV-218431r603259_rule'
  tag stig_id: 'GEN003000'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19904r562454_fix'
  tag 'documentable'
  tag legacy: ['V-976', 'SV-64405']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
