control 'SV-222449' do
  title 'The application must record the username or user ID of the user associated with the event.'
  desc 'When users conduct activity within an application, that user’s identity must be recorded in the audit log. Failing to record the identity of the user responsible for the activity within the application is detrimental to forensic analysis.'
  desc 'check', 'Review and monitor the application logs.

Connect to the application and perform application activity that is allowed by the user such as accessing data or running reports.

Observe if the log includes an entry to indicate the user ID of the user that conducted the activity.

If the user ID is not recorded along with the event in the event log, this is a finding.'
  desc 'fix', 'Configure the application to record the user ID of the user responsible for the log event entry.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24119r493255_chk'
  tag severity: 'medium'
  tag gid: 'V-222449'
  tag rid: 'SV-222449r508029_rule'
  tag stig_id: 'APSC-DV-000700'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-24108r493256_fix'
  tag 'documentable'
  tag legacy: ['V-69379', 'SV-84001']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
