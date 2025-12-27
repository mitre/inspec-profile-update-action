control 'SV-218444' do
  title 'The cronlog file must have mode 0600 or less permissive.'
  desc 'Cron logs contain reports of scheduled system activities and must be protected from unauthorized access or manipulation.'
  desc 'check', 'Check the mode of the cron log file.

Procedure:

Depending on what system is used for log processing either /etc/syslog.conf or /etc/rsyslog.conf will be the logging configuration file.

Check the configured cron log file found in the cron entry in /etc/syslog.conf or /etc/rsyslog.conf (normally /var/log/cron).

# grep cron /etc/syslog.conf
 
Or:

# grep cron /etc/rsyslog.conf

# ls -lL /var/log/cron

If the mode is more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the cron log file.

# chmod 0600 /var/log/cron'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19919r562489_chk'
  tag severity: 'medium'
  tag gid: 'V-218444'
  tag rid: 'SV-218444r603259_rule'
  tag stig_id: 'GEN003180'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19917r562490_fix'
  tag 'documentable'
  tag legacy: ['V-983', 'SV-64317']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
