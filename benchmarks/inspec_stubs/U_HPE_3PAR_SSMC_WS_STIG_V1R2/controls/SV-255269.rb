control 'SV-255269' do
  title 'SSMC web server must use a logging mechanism that is configured to alert the ISSO and SA in the event of a processing failure.'
  desc 'Reviewing log data allows an investigator to recreate the path of an attacker and to capture forensic data for later use. Log data is also essential to system administrators in their daily administrative duties on the hosted system or within the hosted applications. 

If the logging system begins to fail, events will not be recorded. Organizations must define logging failure events, at which time the application or the logging mechanism the application utilizes will provide a warning to the ISSO and SA at a minimum.'
  desc 'check', 'Verify that SSMC is configured to provide an alert to the ISSO and SA when log processing failures occur by doing the following:

Execute status check on remote_syslog_appliance security control:
$ sudo /ssmc/bin/config_security.sh -o remote_syslog_appliance -a status | grep smtp

ssmc.rsyslog.smtp.alert=true
ssmc.rsyslog.smtp.mailFrom=id@domain
ssmc.rsyslog.smtp.recipient=["id1@domain","id2@domain"]
ssmc.rsyslog.smtp.notify-interval=<failure_notify_interval>
ssmc.rsyslog.smtp.server=<smtp_server_ip>
ssmc.rsyslog.smtp.port=<smtp_port>

If the "smtp.alert" is not equal to "true" and the remaining smtp configuration is not established per the site requirements, this is a finding.'
  desc 'fix', 'Configure SSMC  to provide an alert to the ISSO and SA when log processing failures occur by doing the following:

1. Configure rsyslog parameters in /ssmc/conf/security_config.properties like below (use vi editor) -
ssmc.rsyslog.smtp.alert=true
ssmc.rsyslog.smtp.server=<smtp_server_ip>
ssmc.rsyslog.smtp.port=<smtp_port>
ssmc.rsyslog.smtp.recipient=["id1@domain","id2@domain"]
ssmc.rsyslog.smtp.notify-interval=300
ssmc.rsyslog.smtp.mailFrom=id@domain

2. Execute "sudo /ssmc/bin/config_security.sh -o remote_syslog_appliance -a set -f" to commit the configuration and enable the service.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC Web Server'
  tag check_id: 'C-58882r869974_chk'
  tag severity: 'medium'
  tag gid: 'V-255269'
  tag rid: 'SV-255269r879570_rule'
  tag stig_id: 'SSMC-WS-030050'
  tag gtitle: 'SRG-APP-000108-WSR-000166'
  tag fix_id: 'F-58826r869975_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
