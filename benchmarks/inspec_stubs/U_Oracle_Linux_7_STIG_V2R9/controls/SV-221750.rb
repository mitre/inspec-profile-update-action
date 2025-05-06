control 'SV-221750' do
  title 'The Oracle Linux operating system must have cron logging implemented.'
  desc 'Cron logging can be used to trace the successful or unsuccessful execution of cron jobs. It can also be used to spot intrusions into the use of the cron facility by unauthorized and malicious users.'
  desc 'check', 'Verify that "rsyslog" is configured to log cron events.

Check the configuration of "/etc/rsyslog.conf" or "/etc/rsyslog.d/*.conf" files for the cron facility with the following command:

Note: If another logging package is used, substitute the utility configuration file for "/etc/rsyslog.conf" or "/etc/rsyslog.d/*.conf" files.

# grep cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf
cron.* /var/log/cron

If the command does not return a response, check for cron logging all facilities by inspecting the "/etc/rsyslog.conf" or "/etc/rsyslog.d/*.conf" files.

Look for the following entry:

*.* /var/log/messages

If "rsyslog" is not logging messages for the cron facility or all facilities, this is a finding.'
  desc 'fix', 'Configure "rsyslog" to log all cron messages by adding or updating the following line to "/etc/rsyslog.conf" or a configuration file in the /etc/rsyslog.d/ directory:

cron.* /var/log/cron

The rsyslog daemon must be restarted for the changes to take effect:
$ sudo systemctl restart rsyslog.service'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23465r744081_chk'
  tag severity: 'medium'
  tag gid: 'V-221750'
  tag rid: 'SV-221750r744083_rule'
  tag stig_id: 'OL07-00-021100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23454r744082_fix'
  tag 'documentable'
  tag legacy: ['V-99239', 'SV-108343']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
