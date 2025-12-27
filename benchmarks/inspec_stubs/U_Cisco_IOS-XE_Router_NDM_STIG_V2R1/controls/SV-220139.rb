control 'SV-220139' do
  title 'The Cisco router must be configured to send log data to a syslog server for the purpose of forwarding alerts to the administrators and the ISSO.'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, are important in showing whether someone is an internal employee or an outside threat.'
  desc 'check', 'Verify that the router is configured to send logs to a syslog server. The configuration should look similar to the example below:

logging trap notifications
logging x.x.x.x

Note: Default for sending log messages to the syslog server is informational (level 6); hence, the command logging trap informational will not be seen in the configuration. Level of log messages sent to the syslog server can be verified using the show logging command.

If the router is not configured to send log data to the syslog server, this is a finding.'
  desc 'fix', 'Configure the router to send log messages to the syslog server as shown in the example below.

R4(config)#logging host x.x.x.x
R4(config)#logging trap notifications'
  impact 0.7
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-21854r388867_chk'
  tag severity: 'high'
  tag gid: 'V-220139'
  tag rid: 'SV-220139r531083_rule'
  tag stig_id: 'CISC-ND-001450'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-21846r388868_fix'
  tag 'documentable'
  tag legacy: ['SV-105503', 'V-96365']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
