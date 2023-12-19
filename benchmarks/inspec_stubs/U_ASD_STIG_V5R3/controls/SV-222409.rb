control 'SV-222409' do
  title 'The application must automatically remove or disable temporary user accounts 72 hours after account creation.'
  desc 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.

Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation.

If temporary accounts are used, the application must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours starting from the point of account creation.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'If official documentation exist that disallows the use of temporary user accounts within the application, this requirement is not applicable.

Examine the application documentation or interview the application representative to identify how the application users are managed.

Navigate to the screen where user accounts are configured.

Create a test account and determine if there is a setting to specify the user account as being temporary in nature.

Determine if there is an available setting to expire the account after a period of time.

If the application has no ability to specify a user account as being temporary in nature, or if the account has no ability to automatically disable or remove the account after 72 hours after account creation, this is a finding.'
  desc 'fix', 'Configure temporary accounts to be automatically removed or disabled after 72 hours after account creation.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24079r493135_chk'
  tag severity: 'medium'
  tag gid: 'V-222409'
  tag rid: 'SV-222409r879523_rule'
  tag stig_id: 'APSC-DV-000300'
  tag gtitle: 'SRG-APP-000024'
  tag fix_id: 'F-24068r493136_fix'
  tag 'documentable'
  tag legacy: ['V-69299', 'SV-83921']
  tag cci: ['CCI-000016']
  tag nist: ['AC-2 (2)']
end
