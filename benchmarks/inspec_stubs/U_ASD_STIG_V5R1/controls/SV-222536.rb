control 'SV-222536' do
  title 'The application must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Use of passwords for application authentication is intended only for limited situations and should not be used as a replacement for two-factor CAC-enabled authentication.

Examples of situations where a user ID and password might be used include but are not limited to:

- When the application user base does not have a CAC and is not a current DoD employee, member of the military, or a DoD contractor.

- When an application user has been officially designated as a Temporary Exception User; one who is temporarily unable to present a CAC for some reason (lost, damaged, not yet issued, broken card reader) and to satisfy urgent organizational needs must be temporarily permitted to use user ID/password authentication until the problem with CAC use has been remedied.

and

- When the application is publicly available and or hosting publicly releasable data requiring some degree of need-to-know protection.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify if the application uses passwords for user authentication.

If the application does not use passwords, the requirement is not applicable.

Access the application management interface and create a test user account or logon to the system with a test account and access the functionality that provides password change capabilities.

When prompted to provide the password, attempt to create a password shorter than 15 characters in length.

If a password shorter than 15 characters can be created, this is a finding.'
  desc 'fix', 'Configure the application to require 15 characters in the password.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24206r493516_chk'
  tag severity: 'high'
  tag gid: 'V-222536'
  tag rid: 'SV-222536r508029_rule'
  tag stig_id: 'APSC-DV-001680'
  tag gtitle: 'SRG-APP-000164'
  tag fix_id: 'F-24195r493517_fix'
  tag 'documentable'
  tag legacy: ['V-69555', 'SV-84177']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
