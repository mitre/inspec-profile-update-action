control 'SV-95959' do
  title 'The WebSphere Application Server must alert the SA and ISSO, at a minimum, in the event of a log processing failure.'
  desc 'Logs are essential to monitor the health of the system, investigate changes that occurred to the system, or investigate a security incident. When log processing fails, the events during the failure can be lost. To minimize the timeframe of the log failure, an alert needs to be sent to the SA and ISSO at a minimum.

Log processing failures include, but are not limited to, failures in the application server log capturing mechanisms or log storage capacity being reached or exceeded. In some instances, it is preferred to send alarms to individuals rather than to an entire group. Application servers must be able to trigger an alarm and send an alert to, at a minimum, the SA and ISSO in the event there is an application server log processing failure.'
  desc 'check', 'If the SA and ISSO are notified of log processing failures via an alternative notification process, this is not a finding.

In the administrative console, navigate to Security >> Security auditing >> Audit monitor.

If "Enabled monitoring" is not checked and "Monitor notification" is not set to a notification in the notifications list, that includes the SA and ISSO, this is a finding.'
  desc 'fix', 'Establish and utilize a notification process for WebSphere log events or configure WebSphere to send log event alerts via email.

In the administrative console, navigate to Security >> Security auditing >> Audit monitor.

Click on "New" button.

Specify a unique name for the new notification name.

Click "Message log" checkbox.

Select "Email sent to notification list".

Enter SA and ISSO emails in the "Email address to add" field.

Enter the mail server address in the "Outgoing mail (STMP) server" field.

Click ">" to put email in "List of email addresses" field.

Click "OK".

Select the "Enable monitoring" check box to turn on audit failure notifications.

Select the notification configuration to be used from the "Monitor notification" dropdown menu.

Click "OK".

Click "Save".'
  impact 0.3
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80931r1_chk'
  tag severity: 'low'
  tag gid: 'V-81245'
  tag rid: 'SV-95959r1_rule'
  tag stig_id: 'WBSP-AS-000640'
  tag gtitle: 'SRG-APP-000108-AS-000067'
  tag fix_id: 'F-88025r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
