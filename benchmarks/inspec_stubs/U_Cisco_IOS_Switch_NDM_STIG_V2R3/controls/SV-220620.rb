control 'SV-220620' do
  title 'The Cisco switch must be configured to send log data to a central log server for the purpose of forwarding alerts to the administrators and the Information System Security Officer (ISSO).'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can used to detect weaknesses in security that enable the network Information Assurance (IA) team to find and address these weaknesses before breaches can occur. 

Reviewing these logs, whether before or after a security breach, is important in showing whether someone is an internal employee or an outside threat.'
  desc 'check', 'Verify that the switch is configured to send logs to a central log server. The configuration should look similar to the example below:

logging trap notifications
logging x.x.x.x

Note: The default for sending log messages to the syslog server is informational (level 6); hence, the command logging trap information will not be seen in the configuration. The level of log messages sent to the syslog server can be verified using the show logging command.

If the switch is not configured to send log data to the syslog server, this is a finding.'
  desc 'fix', 'Configure the switch to send log messages to the syslog server as shown in the example below:

SW4(config)#logging host x.x.x.x
SW4(config)#logging trap notifications'
  impact 0.7
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22335r507906_chk'
  tag severity: 'high'
  tag gid: 'V-220620'
  tag rid: 'SV-220620r521267_rule'
  tag stig_id: 'CISC-ND-001450'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-22324r507907_fix'
  tag 'documentable'
  tag legacy: ['SV-110469', 'V-101365']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
