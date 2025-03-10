control 'SV-242594' do
  title 'The Cisco ISE must generate a critical alert to be sent to the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without an alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Cisco ISE provides system alarms which notify the administrator when critical system condition occurs. Alarms are displayed in the Alarm dashlet. Administrators can configured the dashlet to receive notification of alarms through e-mail and/or syslog messages.'
  desc 'check', 'Verify the Cisco ISE will notify one or more individuals when there is a Log Collection Error.

From the Web Admin portal:
1. Choose Administration >> System >> Settings >> Alarm Settings.
2. Select "Log Collector Error" from the list of default alarms and click "Edit".
3. Verify that "Enable" is selected.
4. Select "Enter Multiple Emails Separated with Comma".
5. Verify one or more email addresses are configured.

If "Log Collector Error" alarm type is not enabled or email addresses are not configured to receive the alert, this is a finding.'
  desc 'fix', 'Configure Cisco ISE to notify one or more individuals when there is a Log Collection Error.

From the Web Admin portal:
1. Choose Administration >> System >> Settings >> Alarm Settings.
2. Select "Log Collector Error" from the list of default alarms and click "Edit".
3. Select "Enable".
4. Select "Enter Multiple Emails Separated with Comma".
5. Configure email addresses of individuals and organizational accounts to be notified.
6. Click "Submit".'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45869r714090_chk'
  tag severity: 'medium'
  tag gid: 'V-242594'
  tag rid: 'SV-242594r714092_rule'
  tag stig_id: 'CSCO-NC-000200'
  tag gtitle: 'SRG-NET-000335-NAC-001360'
  tag fix_id: 'F-45826r714091_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
