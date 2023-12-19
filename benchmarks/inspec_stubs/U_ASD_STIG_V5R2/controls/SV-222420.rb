control 'SV-222420' do
  title 'The application must notify System Administrators and Information System Security Officers of account removal actions.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply create a new account. Notification of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of application user accounts and notifies administrators and Information System Security Officers (ISSO) exists. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Review the application and system documentation.

Interview the application administrator and determine if the application is configured to utilize a centralized user management system like Active Directory for user management or if the application manages user accounts within the application.

If the application is configured to use an enterprise-based application user management capability that is STIG compliant, the requirement is not applicable.

Ensure application is configured to notify system administrators when accounts are removed by identifying system administrators who will be notified when accounts are removed.

Remove a test account and check with a system administrator to verify notification was received.

If system administrators and ISSOs are not notified when accounts are removed, this is a finding.'
  desc 'fix', 'Configure the application to notify the system administrator and the ISSO when application accounts are removed.'
  impact 0.3
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24090r493168_chk'
  tag severity: 'low'
  tag gid: 'V-222420'
  tag rid: 'SV-222420r508029_rule'
  tag stig_id: 'APSC-DV-000410'
  tag gtitle: 'SRG-APP-000294'
  tag fix_id: 'F-24079r493169_fix'
  tag 'documentable'
  tag legacy: ['SV-83941', 'V-69319']
  tag cci: ['CCI-001686']
  tag nist: ['AC-2 (4)']
end
