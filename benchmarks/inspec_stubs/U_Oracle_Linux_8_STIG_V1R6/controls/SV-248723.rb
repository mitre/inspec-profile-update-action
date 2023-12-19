control 'SV-248723' do
  title 'Cron logging must be implemented in OL 8.'
  desc 'Cron logging can be used to trace the successful or unsuccessful execution of cron jobs. It can also be used to spot intrusions into the use of the cron facility by unauthorized and malicious users.'
  desc 'check', 'Verify that "rsyslog" is configured to log cron events with the following command: 
 
Note: If another logging package is used, substitute the utility configuration file for "/etc/rsyslog.conf" or "/etc/rsyslog.d/*.conf" files. 
 
$ sudo grep cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf 
 
cron.* /var/log/cron 
 
If the command does not return a response, check for cron logging all facilities by inspecting the "/etc/rsyslog.conf" or "/etc/rsyslog.d/*.conf" files. 
 
Look for the following entry: 
 
*.* /var/log/messages 
 
If "rsyslog" is not logging messages for the cron facility or all facilities, this is a finding.'
  desc 'fix', 'Configure "rsyslog" to log all cron messages by adding or updating the following line to "/etc/rsyslog.conf" or a configuration file in the "/etc/rsyslog.d/" directory: 
 
cron.* /var/log/cron 
 
The rsyslog daemon must be restarted for the changes to take effect: 
 
$ sudo systemctl restart rsyslog.service'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52157r779733_chk'
  tag severity: 'medium'
  tag gid: 'V-248723'
  tag rid: 'SV-248723r779735_rule'
  tag stig_id: 'OL08-00-030010'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52111r779734_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
