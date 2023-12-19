control 'SV-222421' do
  title 'The application must automatically audit account enabling actions.'
  desc 'When application accounts are enabled, user accessibility is affected. Accounts are utilized for identifying individual application users or for identifying the application processes themselves. In order to detect and respond to events affecting user accessibility and application processing, applications must audit account removal actions and, as required, notify the appropriate individuals, so they can investigate the event. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes.

Application developers are encouraged to integrate their applications with enterprise-level authentication/access/audit mechanisms such as Syslog, Active Directory or LDAP.'
  desc 'check', 'Examine the application documentation or interview the application representative to identify how the application users are managed.

Interview the application administrator and determine if the application is configured to utilize a centralized user management system such as Active Directory for user management or if the application manages user accounts within the application.

If the application is configured to use an enterprise-based application user management capability that is STIG compliant, the requirement is not applicable.

Identify the location of the audit logs and review the end of the logs.

Access the user account management functionality and enable a test user account.

Examine the log file again and determine if the account enable event was logged. The information logged should, at a minimum, include enough detail to determine which account was enabled and when.

If the account enabling event information was not logged, this is a finding.'
  desc 'fix', 'Configure the application to write a log entry when a user account is enabled. 

At a minimum, ensure account name, date and time of the event are recorded.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24091r918114_chk'
  tag severity: 'medium'
  tag gid: 'V-222421'
  tag rid: 'SV-222421r918115_rule'
  tag stig_id: 'APSC-DV-000420'
  tag gtitle: 'SRG-APP-000319'
  tag fix_id: 'F-24080r493172_fix'
  tag 'documentable'
  tag legacy: ['SV-83943', 'V-69321']
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
