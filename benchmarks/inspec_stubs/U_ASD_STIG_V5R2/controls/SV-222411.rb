control 'SV-222411' do
  title 'The application must automatically disable accounts after a 35 day period of account inactivity.'
  desc 'Attackers that are able to exploit an inactive account can potentially obtain and maintain undetected access to an application. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained. Applications need to track periods of user inactivity and disable accounts after 35 days of inactivity. Such a process greatly reduces the risk that accounts will be hijacked, leading to a data compromise.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.

This policy does not apply to either emergency accounts or infrequently used accounts. Infrequently used accounts are local logon administrator accounts used by system administrators when network or normal logon/access is not available. Emergency accounts are administrator accounts created in response to crisis situations.'
  desc 'check', 'Examine the application documentation or interview the application representative to identify how the application users are managed.

Interview the application administrator and determine if the application is configured to utilize a centralized user management system like Active Directory (AD) for user management or if the application manages user accounts within the application.

If the application is configured to use an enterprise-based application user management capability that is STIG compliant, the requirement is not applicable.

If the application handles the management tasks for user accounts, access the applications user management utility.

Navigate to the screen where user accounts are configured to be disabled after 35 days of inactivity.

Confirm this setting is active.

If the application is not set to expire inactive accounts after 35 days, or if the application has no ability to expire accounts after 35 days of inactivity, this is a finding.'
  desc 'fix', 'Design and configure the application to expire user accounts after 35 days of inactivity.'
  impact 0.3
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24081r493141_chk'
  tag severity: 'low'
  tag gid: 'V-222411'
  tag rid: 'SV-222411r508029_rule'
  tag stig_id: 'APSC-DV-000320'
  tag gtitle: 'SRG-APP-000025'
  tag fix_id: 'F-24070r493142_fix'
  tag 'documentable'
  tag legacy: ['SV-83923', 'V-69301']
  tag cci: ['CCI-000017']
  tag nist: ['AC-2 (3) (d)']
end
