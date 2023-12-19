control 'SV-239923' do
  title 'The Cisco ASA must be configured to generate an immediate real-time alert of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Review the Cisco ASA configuration to verify it is compliant with this requirement as shown in the example below.

logging trap critical
logging host NDM_INTERFACE 10.1.48.10

Note: The parameter critical can replaced with a lesser severity (i.e., error, warning, notice, informational). A logging list can be used as an alternative to the severity level.

If the Cisco ASA is not configured to generate an alert for all audit failure events, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA to send critical to emergency log messages to the syslog server as shown in the example below.

ASA(config)# logging host NDM_INTERFACE 10.1.48.10
ASA(config)# logging trap critical
ASA(config)# end

Note: The parameter critical can replaced with a lesser severity (i.e., error, warning, notice, informational).'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43156r666130_chk'
  tag severity: 'medium'
  tag gid: 'V-239923'
  tag rid: 'SV-239923r666132_rule'
  tag stig_id: 'CASA-ND-000930'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-43115r666131_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
