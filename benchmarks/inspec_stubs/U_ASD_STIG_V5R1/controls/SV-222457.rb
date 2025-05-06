control 'SV-222457' do
  title 'The application must generate audit records when successful/unsuccessful attempts to modify categories of information (e.g., classification levels) occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the application documentation and interview the application administrator.

Identify where the application logs are stored.

Identify any data protections that are required.

Identify any categories of data or classification of data.

If the application requirements do not call for compartmentalized data and data protection, this requirement is not applicable.

Authenticate to the application as a regular user. Using application functionality, attempt to modify data that has been assigned to a protected category.

Perform two modification attempts, one successful and one unsuccessful.

Testing this will require obtaining access to test data that has been assigned to a protected category, or having an authorized user access the data for you.

Review the log data and ensure both the successful and unsuccessful modification attempts are logged.

If the application does not generate an audit record when successful and unsuccessful attempts to modify categories of information occur, this is a finding.'
  desc 'fix', 'Configure the application to create an audit record for both successful and unsuccessful attempts to modify protected categories of information.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24127r493279_chk'
  tag severity: 'medium'
  tag gid: 'V-222457'
  tag rid: 'SV-222457r508029_rule'
  tag stig_id: 'APSC-DV-000780'
  tag gtitle: 'SRG-APP-000498'
  tag fix_id: 'F-24116r493280_fix'
  tag 'documentable'
  tag legacy: ['V-69395', 'SV-84017']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
