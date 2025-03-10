control 'SV-242595' do
  title 'The Cisco ISE must provide an alert to, at a minimum, the SA and ISSO of all audit failure events where the detection and/or prevention function is unable to write events to either local storage or the centralized server.'
  desc 'Without an alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Alerts provide organizations with urgent messages. Alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).

This does not apply to audit logs generated on behalf of the device itself (management).'
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
  tag check_id: 'C-45870r714093_chk'
  tag severity: 'medium'
  tag gid: 'V-242595'
  tag rid: 'SV-242595r714095_rule'
  tag stig_id: 'CSCO-NC-000210'
  tag gtitle: 'SRG-NET-000335-NAC-001370'
  tag fix_id: 'F-45827r714094_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
