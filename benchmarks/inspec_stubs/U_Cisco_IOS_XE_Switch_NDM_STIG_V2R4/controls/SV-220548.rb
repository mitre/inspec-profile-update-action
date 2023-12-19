control 'SV-220548' do
  title 'The Cisco switch must be configured to generate an alert for all audit failure events.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement as shown in the example below:

logging trap critical

Note: The parameter "critical" can replaced with a lesser severity level (i.e. error, warning, notice, informational). Informational is the default severity level; hence, if the severity level is configured to informational, the logging trap command will not be shown in the configuration.

If the Cisco switch is not configured to generate an alert for all audit failure events, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to send critical to emergency log messages to the syslog server as shown in the example below:

SW4(config)#logging trap critical

Note: The parameter "critical" can replaced with a lesser severity level (i.e., error, warning, notice, informational).'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22263r835145_chk'
  tag severity: 'medium'
  tag gid: 'V-220548'
  tag rid: 'SV-220548r835147_rule'
  tag stig_id: 'CISC-ND-001000'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-22252r835146_fix'
  tag 'documentable'
  tag legacy: ['SV-110551', 'V-101447']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
