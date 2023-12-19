control 'SV-220136' do
  title 'The Cisco router must be configured to send log data to a syslog server for the purpose of forwarding alerts to the administrators and the ISSO.'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, are important in showing whether someone is an internal employee or an outside threat.'
  desc 'check', 'Verify that the router is configured to send logs to a syslog server. The configuration should look similar to the example below:

logging x.x.x.x

If the router is not configured to send log data to the syslog server, this is a finding.'
  desc 'fix', 'Configure the router to send log messages to the syslog server as shown in the example below.

R4(config)#logging host x.x.x.x'
  impact 0.7
  ref 'DPMS Target Cisco IOS Router NDM'
  tag check_id: 'C-21850r835063_chk'
  tag severity: 'high'
  tag gid: 'V-220136'
  tag rid: 'SV-220136r879887_rule'
  tag stig_id: 'CISC-ND-001450'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-21844r835064_fix'
  tag 'documentable'
  tag legacy: ['SV-105321', 'V-96183']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
