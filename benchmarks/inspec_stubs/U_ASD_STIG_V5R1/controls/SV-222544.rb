control 'SV-222544' do
  title 'The application must enforce 24 hours/1 day as the minimum password lifetime.'
  desc "Use of passwords for application authentication is intended only for limited situations and should not be used as a replacement for two-factor CAC-enabled authentication.

Examples of situations where a user ID and password might be used include but are not limited to:

- When the application user base does not have a CAC and is not a current DoD employee, member of the military, or a DoD contractor.

- When an application user has been officially designated as a Temporary Exception User; one who is temporarily unable to present a CAC for some reason (lost, damaged, not yet issued, broken card reader) and to satisfy urgent organizational needs must be temporarily permitted to use user ID/password authentication until the problem with CAC use has been remedied.

and

- When the application is publicly available and or hosting publicly releasable data requiring some degree of need-to-know protection.

Enforcing a minimum password lifetime helps prevent repeated password changes to defeat the password reuse or history enforcement requirement.

Restricting this setting limits the user's ability to change their password. Passwords need to be changed at specific policy-based intervals; however, if the application allows the user to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'Review the application documentation and interview the application administrator to identify if the application uses passwords for user authentication.

If the application does not use passwords, the requirement is not applicable.

Access the application management interface and create a test user account or logon to the system with a test account and access the functionality that provides password change capabilities.

Attempt to change the password more than once.

If a password can be changed more than once within 24 hours, the minimum lifetime setting is not set and this is a finding.'
  desc 'fix', 'Configure the application to have a minimum password lifetime of 24 hours.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24214r493540_chk'
  tag severity: 'medium'
  tag gid: 'V-222544'
  tag rid: 'SV-222544r508029_rule'
  tag stig_id: 'APSC-DV-001760'
  tag gtitle: 'SRG-APP-000173'
  tag fix_id: 'F-24203r493541_fix'
  tag 'documentable'
  tag legacy: ['V-69571', 'SV-84193']
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
