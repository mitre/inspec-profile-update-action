control 'SV-104499' do
  title 'Symantec ProxySG must generate an alert to the console when a log processing failure is detected such as loss of communications with the Central Log Server or log records are no longer being sent.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without an alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages.'
  desc 'check', 'Verify the Symantec ProxySG is configured to send alerts when event logging fails. 

1. Log on to the Web Management Console.
2. Click Maintenance >> Events Logging.
3. Confirm that "Severe" is checked.
4. Select the "Mail" tab and confirm an email address of an administrator is entered.

If Symantec ProxySG does not generate an alert to the console when a log processing failure is detected such as loss of communications with the Central Log Server or log records are no longer being sent, this is a finding.'
  desc 'fix', 'Configure the ProxySG to send notifications. 

1. Log on to the Web Management Console.
2. Click Maintenance >> Events Logging.
3. Select "Severe".
4. Select the "Mail" tab and enter the email address to receive the email alert.
5. Click "Apply".'
  impact 0.3
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93859r1_chk'
  tag severity: 'low'
  tag gid: 'V-94669'
  tag rid: 'SV-104499r1_rule'
  tag stig_id: 'SYMP-NM-000090'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-100787r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
