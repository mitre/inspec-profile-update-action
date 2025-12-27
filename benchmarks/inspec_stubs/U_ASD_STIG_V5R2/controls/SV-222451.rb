control 'SV-222451' do
  title 'The application must generate audit records when successful/unsuccessful attempts to access security objects occur.'
  desc 'Security objects represent application objects that provide or require security protections or have a security role within the application. Examples include but are not limited to, files, application modules, folders, and database records. Essentially, if permissions are assigned to protect it, it can be considered a security object. Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the application documentation and interview the application administrator.

Identify where the application logs are stored.

Identify application functionality that provides privilege or permission settings to security objects within the application.
This can be an application function that assigns privileges to an application object or data element.

Authenticate to the application as a regular user. Using application functionality, attempt to access the security object within the application.

Perform two attempts, one successfully and one unsuccessfully.

Review the log data and ensure both the successful and unsuccessful access attempts are logged.

If the application does not generate an audit record when successful and unsuccessful attempts to access security objects occur, this is a finding.'
  desc 'fix', 'Configure the application to create an audit record for both successful and unsuccessful attempts to access security objects.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24121r493261_chk'
  tag severity: 'medium'
  tag gid: 'V-222451'
  tag rid: 'SV-222451r508029_rule'
  tag stig_id: 'APSC-DV-000720'
  tag gtitle: 'SRG-APP-000492'
  tag fix_id: 'F-24110r493262_fix'
  tag 'documentable'
  tag legacy: ['SV-84005', 'V-69383']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
