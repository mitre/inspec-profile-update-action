control 'SV-222453' do
  title 'The application must generate audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Categories of information is information that is identified as being sensitive or requiring additional protection from regular user access. The data is accessed on a need to know basis and has been assigned a category or a classification in order to assign protections and track access.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the application documentation and interview the application administrator. Identify where the application logs are stored.

Identify any data protections that are required.

Identify any categories of data or classification of data.

If the application requirements do not call for compartmentalized data and data protection, this requirement is not applicable.

Authenticate to the application as a regular user. Using application functionality, attempt to access data that has been assigned to a protected category.

Perform two access attempts, one successful and one unsuccessful.

Testing this will require obtaining access to test data that has been assigned to a protected category, or having an authorized user access the data for you.

Review the log data and ensure both the successful and unsuccessful access attempts are logged.

If the application does not generate an audit record when successful and unsuccessful attempts to access categories of information occur, this is a finding.'
  desc 'fix', 'Configure the application to create an audit record for both successful and unsuccessful attempts to access protected categories of information.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24123r493267_chk'
  tag severity: 'medium'
  tag gid: 'V-222453'
  tag rid: 'SV-222453r508029_rule'
  tag stig_id: 'APSC-DV-000740'
  tag gtitle: 'SRG-APP-000494'
  tag fix_id: 'F-24112r493268_fix'
  tag 'documentable'
  tag legacy: ['SV-84009', 'V-69387']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
