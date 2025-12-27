control 'SV-222413' do
  title 'The application must automatically audit account creation.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply create a new account. Auditing of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail documents the creation of application user accounts and, as required, notifies administrators and/or application owners exists. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Examine the application documentation to identify how the application users are managed.

Interview the application administrator and determine if the application is configured to utilize a centralized user management system like Active Directory for user management or if the application manages user accounts within the application.

If the application is configured to use an enterprise-based application user management capability that is STIG compliant, the requirement is not applicable.

Identify the location of the audit logs and review the end of the logs.

Access the user account management functionality and create a new user account.

Examine the log file again and determine if the account creation event was logged. The information logged should, at a minimum, include enough detail to determine which account was created and when.

If the account creation event was not logged, this is a finding.'
  desc 'fix', 'Configure the application to write a log entry when a new user account is created.

At a minimum, ensure account name, date and time of the event are recorded.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24083r493147_chk'
  tag severity: 'medium'
  tag gid: 'V-222413'
  tag rid: 'SV-222413r879525_rule'
  tag stig_id: 'APSC-DV-000340'
  tag gtitle: 'SRG-APP-000026'
  tag fix_id: 'F-24072r493148_fix'
  tag 'documentable'
  tag legacy: ['V-69305', 'SV-83927']
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
