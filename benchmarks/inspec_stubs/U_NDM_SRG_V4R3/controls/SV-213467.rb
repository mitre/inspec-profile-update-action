control 'SV-213467' do
  title 'The network device must be configured to send log data to at least two central log servers for the purpose of forwarding alerts to the administrators and the information system security officer (ISSO).'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, are important in showing whether someone is an internal employee or an outside threat.'
  desc 'check', 'Verify that the network device is configured to send log data to at least two central log servers. 

If the network device is not configured to send log data to at least two central log servers, this is a finding.'
  desc 'fix', 'Configure the network device to send log data to at least two central log servers.'
  impact 0.7
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-14692r916112_chk'
  tag severity: 'high'
  tag gid: 'V-213467'
  tag rid: 'SV-213467r916114_rule'
  tag stig_id: 'SRG-APP-000516-NDM-000350'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-14690r916113_fix'
  tag 'documentable'
  tag legacy: ['SV-108121', 'V-99017']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
