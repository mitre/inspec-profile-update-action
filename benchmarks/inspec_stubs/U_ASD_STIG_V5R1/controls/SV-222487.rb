control 'SV-222487' do
  title 'The application must provide the capability to centrally review and analyze audit records from multiple components within the system.'
  desc 'Successful incident response and auditing relies on timely, accurate system information and analysis in order to allow the organization to identify and respond to potential incidents in a proficient manner. If the application does not provide the ability to centrally review the application logs, forensic analysis is negatively impacted.

Segregation of logging data to multiple disparate computer systems is counterproductive and makes log analysis and log event alarming difficult to implement and manage, particularly when the system or application has multiple logging components written to different locations or systems.

Automated mechanisms for centralized reviews and analyses include, for example, Security Information Management products.'
  desc 'check', "Review system documentation and interview application administrator for details regarding application architecture and logging configuration.  Identify the application components, the logs that are associated with the components and the locations of the logs.

If the application utilizes a centralized logging system that provides the capability to review the log files from one central location, this requirement is not applicable.

Access the application's log management utility and review the log files.  Ensure all of the applications logs are reviewable from within the centralized log management function and access to other systems in order to review application logs are not required.

If all of the application logs are not reviewable from a central location, this is a finding."
  desc 'fix', 'Configure the application so all of the applications logs are available for review from one centralized location.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24157r493369_chk'
  tag severity: 'medium'
  tag gid: 'V-222487'
  tag rid: 'SV-222487r508029_rule'
  tag stig_id: 'APSC-DV-001130'
  tag gtitle: 'SRG-APP-000111'
  tag fix_id: 'F-24146r493370_fix'
  tag 'documentable'
  tag legacy: ['SV-84079', 'V-69457']
  tag cci: ['CCI-000154']
  tag nist: ['AU-6 (4)']
end
