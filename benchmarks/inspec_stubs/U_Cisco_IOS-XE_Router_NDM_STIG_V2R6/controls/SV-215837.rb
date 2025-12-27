control 'SV-215837' do
  title 'The Cisco router must be configured to generate an alert for all audit failure events.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement as shown in the example below.

logging trap critical

Note: The parameter "critical" can replaced with a lesser severity level (i.e. error, warning, notice, informational). Informational is the default severity level; hence, if the severity level is configured to informational, the logging trap command will not be shown in the configuration.

If the Cisco router is not configured to generate an alert for all audit failure events, this is a finding.'
  desc 'fix', 'Configure the Cisco router to send critical to emergency log messages to the syslog server as shown in the example below.

R4(config)#logging trap critical

Note: The parameter "critical" can replaced with a lesser severity level (i.e., error, warning, notice, informational).'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17076r835114_chk'
  tag severity: 'medium'
  tag gid: 'V-215837'
  tag rid: 'SV-215837r879733_rule'
  tag stig_id: 'CISC-ND-001000'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-17074r835115_fix'
  tag 'documentable'
  tag legacy: ['V-96301', 'SV-105439']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
