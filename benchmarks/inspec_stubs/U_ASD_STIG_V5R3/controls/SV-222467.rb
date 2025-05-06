control 'SV-222467' do
  title 'The application must generate audit records for all account creations, modifications, disabling, and termination events.'
  desc 'When application user accounts are created, modified, disabled or terminated the event must be logged.

Centralized management of user accounts allows for rapid response to user related security events and also provides ease of management.

Allowing the centralized user management solution to log these events is acceptable practice; however, if the application provides a user management interface to manage these tasks, the application must also log these events.

Application developers are encouraged to integrate their applications with enterprise-level authentication/access/audit mechanisms such as Syslog, Active Directory or LDAP.'
  desc 'check', 'Examine the application documentation or interview the application representative to identify how the application users are managed.

Interview the application administrator and determine if the application is configured to utilize a centralized user management system such as Active Directory for user management or if the application manages user accounts within the application.

If the application is configured to use an enterprise-based application user management capability that is STIG compliant, the requirement is not applicable.

Identify the location of the audit logs and review the end of the logs.

Access the user account management functionality.

Create an application test account and then review the log to ensure a log record that documents the event is created.

Modify the test account and then review the log to ensure a log record that documents the event is created.

Disable the test account and then review the log to ensure a log record that documents the event is created.

Terminate/remove the test account and then review the log to ensure a log record that documents the event is created.

If log events are not created that document all of these events, this is a finding.

If some but not all of the aforementioned events are documented in the logs, this is a finding.

Findings should document which of the events was not logged.'
  desc 'fix', 'Configure the application to log user account creation, modification, disabling, and termination events.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24137r918116_chk'
  tag severity: 'medium'
  tag gid: 'V-222467'
  tag rid: 'SV-222467r918117_rule'
  tag stig_id: 'APSC-DV-000880'
  tag gtitle: 'SRG-APP-000509'
  tag fix_id: 'F-24126r493310_fix'
  tag 'documentable'
  tag legacy: ['SV-84037', 'V-69415']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
