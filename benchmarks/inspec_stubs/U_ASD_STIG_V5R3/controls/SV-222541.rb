control 'SV-222541' do
  title 'The application must require the change of at least 8 of the total number of characters when passwords are changed.'
  desc 'Use of passwords for application authentication is intended only for limited situations and should not be used as a replacement for two-factor CAC-enabled authentication.

Examples of situations where a user ID and password might be used include but are not limited to:

- When the application user base does not have a CAC and is not a current DoD employee, member of the military, or a DoD contractor.

- When an application user has been officially designated as a Temporary Exception User; one who is temporarily unable to present a CAC for some reason (lost, damaged, not yet issued, broken card reader) and to satisfy urgent organizational needs must be temporarily permitted to use user ID/password authentication until the problem with CAC use has been remedied.

and

- When the application is publicly available and or hosting publicly releasable data requiring some degree of need-to-know protection.

Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify if the application uses passwords for user authentication.

If the application does not use passwords, the requirement is not applicable.

Access the application management interface and create a test user account or logon to the system with a test account and access the functionality that provides password change capabilities.

When prompted to provide the password, attempt to change less than 8 characters of the total number of characters in the password.

If less than 8 characters of the password are changed, this is a finding.'
  desc 'fix', 'Configure the application to require the change of at least 8 characters in the password when passwords are changed.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24211r493531_chk'
  tag severity: 'medium'
  tag gid: 'V-222541'
  tag rid: 'SV-222541r879607_rule'
  tag stig_id: 'APSC-DV-001730'
  tag gtitle: 'SRG-APP-000170'
  tag fix_id: 'F-24200r493532_fix'
  tag 'documentable'
  tag legacy: ['V-69565', 'SV-84187']
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
