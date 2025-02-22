control 'SV-222547' do
  title 'The application must allow the use of a temporary password for system logons with an immediate change to a permanent password.'
  desc 'Use of passwords for application authentication is intended only for limited situations and should not be used as a replacement for two-factor CAC-enabled authentication.

Examples of situations where a user ID and password might be used include but are not limited to:

- When the application user base does not have a CAC and is not a current DoD employee, member of the military, or a DoD contractor.

- When an application user has been officially designated as a Temporary Exception User; one who is temporarily unable to present a CAC for some reason (lost, damaged, not yet issued, broken card reader) and to satisfy urgent organizational needs must be temporarily permitted to use user ID/password authentication until the problem with CAC use has been remedied.

and

- When the application is publicly available and or hosting publicly releasable data requiring some degree of need-to-know protection.

Without providing this capability, an account may be created without a password. Non-repudiation cannot be guaranteed once an account is created if a user is not forced to change the temporary password upon initial logon.

Temporary passwords are typically used to allow access to applications when new accounts are created or passwords are changed. It is common practice for administrators to create temporary passwords for user accounts which allow the users to log on, yet force them to change the password once they have successfully authenticated.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify if the application uses passwords for user authentication.

If the application does not use passwords, the requirement is not applicable.

Access the application management interface and view the user password settings page.

Review user password settings and validate the application is configured to specify when a password is temporary and force a password change when the administrator either creates a new user account or changes a user’s password.

If the application can not specify a password as temporary and force the user to change the temporary password upon successful authentication, this is a finding.'
  desc 'fix', 'Configure the application to specify when a password is temporary and change the temporary password on the first use.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24217r493549_chk'
  tag severity: 'medium'
  tag gid: 'V-222547'
  tag rid: 'SV-222547r508029_rule'
  tag stig_id: 'APSC-DV-001790'
  tag gtitle: 'SRG-APP-000397'
  tag fix_id: 'F-24206r493550_fix'
  tag 'documentable'
  tag legacy: ['SV-84199', 'V-69577']
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
