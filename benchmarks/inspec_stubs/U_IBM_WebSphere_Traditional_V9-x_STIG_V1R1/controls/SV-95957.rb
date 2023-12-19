control 'SV-95957' do
  title 'The WebSphere Application Server must provide an immediate real-time alert to authorized users of all log failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process logs as required. Log processing failures include software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded. Notification of the failure event will allow administrators to take actions so that logs are not lost.'
  desc 'check', 'If notifications of log processing failures are done via an alternative notification process, this is not a finding.

In the administrative console, navigate to Security >> Security auditing >> Audit monitor.

If "Enabled monitoring" is not checked and "Monitor notification" is not set to a name in the notifications list, this is a finding.'
  desc 'fix', 'Establish and utilize a notification process for WebSphere log events or configure WebSphere to send log events alerts via email.

In the administrative console, navigate to Security >> Security auditing >> Audit monitor.

Select a "Monitor" notification from the dropdown box or create a new notification.

Click on "New".

Specify a unique name for the new notification.

Click "Message log" checkbox.

Select "Email sent to notification list".

Enter emails in the "Email address to add" field.

Enter the mail server address in the "Outgoing mail (STMP) server" field.

Click ">" to put email in "List of email addresses" field.

Click "OK".

Select the "Enable monitoring" check box to turn on audit failure notifications.

Select the notification configuration to be used from the "Monitor notification" dropdown menu.

Click "OK".

Click "Save".'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80929r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81243'
  tag rid: 'SV-95957r1_rule'
  tag stig_id: 'WBSP-AS-000630'
  tag gtitle: 'SRG-APP-000360-AS-000066'
  tag fix_id: 'F-88023r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
