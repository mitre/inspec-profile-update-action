control 'SV-220568' do
  title 'The Cisco switch must be configured to send log data to at least two central log servers for the purpose of forwarding alerts to the administrators and the information system security officer (ISSO).'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, are important in showing whether someone is an internal employee or an outside threat.'
  desc 'check', 'Verify that the switch is configured to send logs to at least two central log servers. The configuration should look similar to the example below:

logging x.x.x.x
logging x.x.x.x

If the switch is not configured to send log data to the syslog servers, this is a finding.'
  desc 'fix', 'Configure the switch to send log messages to the syslog servers as shown in the example below:

SW4(config)#logging host x.x.x.x
SW4(config)#logging host x.x.x.x'
  impact 0.7
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22283r916067_chk'
  tag severity: 'high'
  tag gid: 'V-220568'
  tag rid: 'SV-220568r916114_rule'
  tag stig_id: 'CISC-ND-001450'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-22272r916068_fix'
  tag 'documentable'
  tag legacy: ['SV-110591', 'V-101487']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
