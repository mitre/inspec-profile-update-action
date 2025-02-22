control 'SV-222414' do
  title 'The application must automatically audit account modification.'
  desc 'One way for an attacker to establish persistent access is for the attacker to modify or copy an existing account. Auditing of account modification is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail documents the modification of application user accounts. Such a process greatly reduces the risk that accounts will be surreptitiously modified and provides logging that can be used for forensic purposes.

To address account requirements and to ensure application accounts follow requirements consistently, application developers are strongly encouraged to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Examine the application documentation to identify how the application users are managed.

Interview the application administrator and determine if the application is configured to utilize a centralized user management system like Active Directory for user management or if the application manages user accounts within the application.

If the application is configured to use an enterprise-based application user management capability that is STIG compliant, the requirement is not applicable.

Identify the location of the audit logs and review the end of the logs.

Access the user account management functionality and modify a test user account.

Examine the log file again and determine if the account event was logged. The information logged should, at a minimum, include enough detail to determine which account was modified and when.

If the account modification event information was not logged, this is a finding.'
  desc 'fix', 'Configure the application to write a log entry when a user account is modified.

At a minimum, ensure account name, date and time of the event are recorded.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24084r493150_chk'
  tag severity: 'medium'
  tag gid: 'V-222414'
  tag rid: 'SV-222414r879526_rule'
  tag stig_id: 'APSC-DV-000350'
  tag gtitle: 'SRG-APP-000027'
  tag fix_id: 'F-24073r493151_fix'
  tag 'documentable'
  tag legacy: ['V-69307', 'SV-83929']
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
