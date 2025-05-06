control 'SV-101255' do
  title 'The Juniper router must be configured to generate an alert for all audit failure events.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement as shown in the example below.

system {
   syslog {
        host x.x.x.x {
            any critical;
        }
    }

Note: The parameter "critical" can be replaced with a lesser severity level (i.e., error, warning, notice, info).

If the router is not configured to generate an alert for all audit failure events, this is a finding.'
  desc 'fix', 'Configure the router to send critical to emergency log messages to the syslog server as shown in the example below.

set syslog host x.x.x.x any critical

Note: The parameter "critical" can replaced with a lesser severity level (i.e., error, warning, notice, info).'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-90309r3_chk'
  tag severity: 'medium'
  tag gid: 'V-91155'
  tag rid: 'SV-101255r1_rule'
  tag stig_id: 'JUNI-ND-000990'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-97353r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
