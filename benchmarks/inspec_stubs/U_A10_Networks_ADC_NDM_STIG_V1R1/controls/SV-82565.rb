control 'SV-82565' do
  title 'The A10 Networks ADC must send Emergency messages to the Console, Syslog, and Monitor.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Review the device configuration.

The following command shows the logging policy:
show log policy

If the level of logging for the Console, Syslog, and Monitor is not at least Emergency, this is a finding. 

Since each severity level includes the levels below it, other levels are permitted. However, the debugging level may generate too many messages when used and must be used carefully.'
  desc 'fix', 'The following command sets the severity level for a particular destination:
log [destination] [severity]

Note: Each severity level includes the levels below it. However, the debugging level may generate too many messages when used and must be used carefully.'
  impact 0.3
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68635r1_chk'
  tag severity: 'low'
  tag gid: 'V-68075'
  tag rid: 'SV-82565r1_rule'
  tag stig_id: 'AADC-NM-000098'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-74191r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
