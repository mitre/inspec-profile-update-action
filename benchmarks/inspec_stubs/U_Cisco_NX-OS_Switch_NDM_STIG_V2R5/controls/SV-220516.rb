control 'SV-220516' do
  title 'The Cisco switch must be configured to send log data to at least two central log servers for the purpose of forwarding alerts to the administrators and the information system security officer (ISSO).'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, are important in showing whether someone is an internal employee or an outside threat.'
  desc 'check', 'Verify that the switch is configured to send logs to at least two syslog servers. The configuration should look similar to the example below:

logging server 10.1.48.10 6
logging server 10.1.48.11 6

If the switch is not configured to send log data to the syslog servers, this is a finding.'
  desc 'fix', 'Configure the switch to send log messages to the syslog servers as shown in the example below:

SW4(config)# logging server 10.1.48.10 6
SW4(config)# logging server 10.1.48.11 6'
  impact 0.7
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22231r916094_chk'
  tag severity: 'high'
  tag gid: 'V-220516'
  tag rid: 'SV-220516r916114_rule'
  tag stig_id: 'CISC-ND-001450'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-22220r916095_fix'
  tag 'documentable'
  tag legacy: ['SV-110681', 'V-101577']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
