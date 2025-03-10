control 'SV-222463' do
  title 'The application must generate audit records for privileged activities or other system-level access.'
  desc 'Privileged activities include the tasks or actions taken by users in an administrative role (admin, backup operator, manager, etc.) which are used to manage or reconfigure application function. Examples include but are not limited to:

Modifying application logging verbosity, starting or stopping of application services, application user account management, managing application functionality, or otherwise changing the underlying application capabilities such as adding a new application module or plugin.

Privileged access does not include an application design which does not modify the application but does provide users with the functionality or the ability to manage their own user specific preferences or otherwise tailor the application to suit individual user needs based upon choices or selections built into the application.'
  desc 'check', 'Review and monitor the application logs.

Authenticate to the application as a privileged user and observe if the log includes an entry to indicate the user’s authentication was successful.

Perform actions as an admin or other privileged user such as modifying the logging verbosity, or starting or stopping an application service, or terminating a test user session.

If log events that correspond with the actions performed are not recorded in the logs, this is a finding.'
  desc 'fix', 'Configure the application to write a log entry when privileged activities or other system-level events occur.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24133r493297_chk'
  tag severity: 'medium'
  tag gid: 'V-222463'
  tag rid: 'SV-222463r508029_rule'
  tag stig_id: 'APSC-DV-000840'
  tag gtitle: 'SRG-APP-000504'
  tag fix_id: 'F-24122r493298_fix'
  tag 'documentable'
  tag legacy: ['SV-84029', 'V-69407']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
