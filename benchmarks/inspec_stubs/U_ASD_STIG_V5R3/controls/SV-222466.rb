control 'SV-222466' do
  title 'The application must generate audit records for all direct access to the information system.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

When an application provides direct access to underlying OS features and functions, that access must be audited.
Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the application documentation and interview the application administrator.

Identify if the application implements a direct access feature or function that allows users to directly access the underlying OS.

Direct access includes but is not limited to: executing OS commands, navigating the file system, manipulating system resources such as print queues, or reading files hosted on the OS that are not specifically shared or made available on the website.

If the application does not provide direct access to the system, this requirement is not applicable.

Access the application logs.

Access the application as a user or test user with appropriate permissions and attempt to execute application features and functions that provide direct access to the system.

Review the logs and ensure the actions executed were logged.

Log information must include the user responsible for executing the action, the action executed, and the result of the action.

If the application does not log all direct access to the system, this is a finding.'
  desc 'fix', 'Configure the application to log all direct access to the system.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24136r493306_chk'
  tag severity: 'medium'
  tag gid: 'V-222466'
  tag rid: 'SV-222466r879879_rule'
  tag stig_id: 'APSC-DV-000870'
  tag gtitle: 'SRG-APP-000508'
  tag fix_id: 'F-24125r493307_fix'
  tag 'documentable'
  tag legacy: ['SV-84035', 'V-69413']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
