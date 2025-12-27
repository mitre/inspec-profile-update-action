control 'SV-222459' do
  title 'The application must generate audit records when successful/unsuccessful attempts to delete security levels occur.'
  desc 'A security level denotes a permissions or authorization capability within the application. This is most often associated with a user role. Attempts to delete a security level can be construed as an attempt to change the configuration of the application so as to delete an existing security role. Some applications may or may not provide this capability.

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the application documentation and interview the application administrator.

Identify where the application logs are stored.

Identify application functionality that provides privilege escalation or access to additional security levels within the application.

This can be performing a function that escalates the privileges of the user, or accessing a protected area of the application that requires additional authentication in order to access.

Authenticate to the application as a regular user. Using application functionality, attempt to delete permissions of a different security level or domain within the application.

Perform two attempts, one successfully and one unsuccessfully.

Review the log data and ensure the deletion events, both successful and unsuccessful are logged.

If the application does not generate an audit record when successful and unsuccessful attempts to delete permissions regarding the security levels occur, this is a finding.'
  desc 'fix', 'Configure the application to create an audit record for both successful and unsuccessful attempts to delete security levels.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24129r493285_chk'
  tag severity: 'medium'
  tag gid: 'V-222459'
  tag rid: 'SV-222459r508029_rule'
  tag stig_id: 'APSC-DV-000800'
  tag gtitle: 'SRG-APP-000500'
  tag fix_id: 'F-24118r493286_fix'
  tag 'documentable'
  tag legacy: ['SV-84021', 'V-69399']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
