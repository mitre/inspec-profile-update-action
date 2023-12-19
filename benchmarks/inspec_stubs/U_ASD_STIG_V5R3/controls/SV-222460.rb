control 'SV-222460' do
  title 'The application must generate audit records when successful/unsuccessful attempts to delete application database security objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the application documentation and interview the application administrator.

Identify where the application logs are stored.

Identify application functionality that provides privilege or permission settings to database security objects within the application. This can be an application function that assigns privileges to an application object or data element.

Authenticate to the application as a regular user. Using application functionality, attempt to delete the database security object within the application.

Perform two attempts, one successfully and one unsuccessfully.

Review the log data and ensure the deletion events, both successful and unsuccessful, are logged.

If the application does not generate an audit record when successful and unsuccessful attempts to delete database security objects occur, this is a finding.'
  desc 'fix', 'Configure the application to create an audit record for both successful and unsuccessful attempts to delete database security objects.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24130r493288_chk'
  tag severity: 'medium'
  tag gid: 'V-222460'
  tag rid: 'SV-222460r879872_rule'
  tag stig_id: 'APSC-DV-000810'
  tag gtitle: 'SRG-APP-000501'
  tag fix_id: 'F-24119r493289_fix'
  tag 'documentable'
  tag legacy: ['SV-84023', 'V-69401']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
