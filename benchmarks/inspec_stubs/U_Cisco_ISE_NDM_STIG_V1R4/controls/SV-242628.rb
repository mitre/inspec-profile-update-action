control 'SV-242628' do
  title 'The Cisco ISE must send an alarm to one or more individuals when the monitoring collector process has an error or failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without an alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Cisco ISE provides system alarms which notify the administrator when critical system condition occurs. Alarms are displayed in the Alarm dashlet. Administrators can configured the dashlet to receive notification of alarms through e-mail and/or syslog messages.

SNMP alerts may also be used to fulfill this requirement.'
  desc 'check', 'Verify the Cisco ISE notifies one or more individuals when the monitoring collector process is unable to persist the audit logs generated from the policy service nodes.

1. Choose Administration >> System >> Settings >> Alarm Settings.
2. Select "Log Collector Error" from the list of default alarms and click "Edit".
3. Verify that "Enable" is selected.
4. Select "Enter Multiple Emails Separated with Comma".
5. Verify one or more email addresses are configured.

If "Log Collector Error" alarm type is not enabled or email addresses are not configured to receive the alert, this is a finding.'
  desc 'fix', 'Configure Cisco ISE to notify one or more individuals when the monitoring collector process is unable to persist the audit logs generated from the policy service nodes.

1. Choose Administration >> System >> Settings >> Alarm Settings.
2. Select "Log Collector Error" from the list of default alarms and click "Edit".
3. Select "Enable".
4. Select "Enter Multiple Emails Separated with Comma".
5. Configure email addresses of individuals to be notified.
6. Click "Submit".'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45903r714192_chk'
  tag severity: 'medium'
  tag gid: 'V-242628'
  tag rid: 'SV-242628r851059_rule'
  tag stig_id: 'CSCO-NM-000220'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-45860r714193_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
