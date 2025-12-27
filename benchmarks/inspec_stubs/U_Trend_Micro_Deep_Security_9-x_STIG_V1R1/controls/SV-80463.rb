control 'SV-80463' do
  title 'Trend Deep Security must provide an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure an immediate real-time alert is provided to the SA and ISSO, at a minimum, of all audit failure events requiring real-time alerts.

Analyze the system using the Administration >> System Settings >> Alerts tab. Review the email address listed in the “Alert Event Forwarding (From The Manager).” 

If this email address is not present or does not belong to a distribution for system administrators and ISSOs, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to provide an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events requiring real-time alerts.

Configure Events and Alerts to notify the SA and ISSO using the Administration >> System Settings >> Alerts tab.
Insert a distribution email address into the “Alert Event Forwarding (From The Manager).” The distribution email address must be configured within Exchange or other email server and must associate the SA and ISSO accounts reviewing and/or managing the system.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66621r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65973'
  tag rid: 'SV-80463r1_rule'
  tag stig_id: 'TMDS-00-000275'
  tag gtitle: 'SRG-APP-000360'
  tag fix_id: 'F-72049r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
