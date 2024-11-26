control 'SV-239943' do
  title 'The Cisco ASA must be configured to send log data to a central log server for the purpose of forwarding alerts to organization-defined personnel and/or the firewall administrator.'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, are important in showing whether someone is an internal employee or an outside threat. The ISSM or ISSO may designate the firewall/system administrator or other authorized personnel to receive the alert within the specified time, validate the alert, and then forward only validated alerts to the ISSM and ISSO.'
  desc 'check', 'Verify the ASA is configured to send logs to a syslog server. The configuration should look similar to the example below.

logging trap notifications
logging host NDM_INTERFACE 10.1.48.10 6/1514

Note: A logging list can be used as an alternative to the severity level.

If the ASA is not configured to send log data to the syslog server, this is a finding.'
  desc 'fix', 'Configure the ASA to send log messages to the syslog server as shown in the example below.

ASA(config)# logging host NDM_INTERFACE 10.1.48.10 6/1514
ASA(config)# logging trap notifications 
ASA(config)# end'
  impact 0.7
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43176r666190_chk'
  tag severity: 'high'
  tag gid: 'V-239943'
  tag rid: 'SV-239943r863234_rule'
  tag stig_id: 'CASA-ND-001410'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-43135r666191_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
