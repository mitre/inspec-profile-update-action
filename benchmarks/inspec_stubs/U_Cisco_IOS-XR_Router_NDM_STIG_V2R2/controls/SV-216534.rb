control 'SV-216534' do
  title 'The Cisco router must be configured to generate an alert for all audit failure events.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement as shown in the example below.

logging 10.1.12.7 vrf default severity critical

Note: The parameter "critical" can be replaced with a lesser severity level (i.e., error, warning, notice, informational). 

If the Cisco router is not configured to generate an alert for all audit failure events, this is a finding.'
  desc 'fix', 'Configure the Cisco router to send critical to emergency log messages to the syslog server as shown in the example below.

RP/0/0/CPU0:R3(config)#logging 10.1.12.7 severity critical

Note: The parameter "critical" can replaced with a lesser severity level (i.e., error, warning, notice, informational).'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17769r288288_chk'
  tag severity: 'medium'
  tag gid: 'V-216534'
  tag rid: 'SV-216534r531088_rule'
  tag stig_id: 'CISC-ND-001000'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-17766r288289_fix'
  tag 'documentable'
  tag legacy: ['SV-105585', 'V-96447']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
