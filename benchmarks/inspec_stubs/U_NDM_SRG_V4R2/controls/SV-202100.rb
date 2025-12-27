control 'SV-202100' do
  title 'The network device must generate an immediate real-time alert of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Determine if the network device generates an immediate alert of all audit failure events requiring real-time alerts.

This requirement may be verified by configuration review or validated test results.

If an immediate alert of all audit failure events requiring real-time alerts is not generated, this is a finding.'
  desc 'fix', 'Configure the network device to generate an immediate real-time alert of all audit failure events requiring real-time alerts.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2226r381932_chk'
  tag severity: 'medium'
  tag gid: 'V-202100'
  tag rid: 'SV-202100r879733_rule'
  tag stig_id: 'SRG-APP-000360-NDM-000295'
  tag gtitle: 'SRG-APP-000360'
  tag fix_id: 'F-2227r381933_fix'
  tag 'documentable'
  tag legacy: ['SV-69325', 'V-55079']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
