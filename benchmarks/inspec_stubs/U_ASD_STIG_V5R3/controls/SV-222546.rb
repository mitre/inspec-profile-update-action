control 'SV-222546' do
  title 'The application must prohibit password reuse for a minimum of five generations.'
  desc 'Use of passwords for application authentication is intended only for limited situations and should not be used as a replacement for two-factor CAC-enabled authentication.

Examples of situations where a user ID and password might be used include but are not limited to:

- When the application user base does not have a CAC and is not a current DoD employee, member of the military, or a DoD contractor.

- When an application user has been officially designated as a Temporary Exception User; one who is temporarily unable to present a CAC for some reason (lost, damaged, not yet issued, broken card reader) and to satisfy urgent organizational needs must be temporarily permitted to use user ID/password authentication until the problem with CAC use has been remedied.

and

- When the application is publicly available and or hosting publicly releasable data requiring some degree of need-to-know protection.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

To meet password policy requirements, passwords need to be changed at specific policy-based intervals.

If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify if the application uses passwords for user authentication.

If the application does not use passwords, the requirement is not applicable.

Access the application management interface and view the user password settings page.

Review user password settings and validate the application is configured to prohibit password reuse for a minimum of 5 password generations.

If the application does not prevent users from reusing their previous 5 passwords, or if the application does not have the ability to control this setting, this is a finding.'
  desc 'fix', 'Configure the application to prohibit password reuse for up to 5 passwords.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24216r493546_chk'
  tag severity: 'medium'
  tag gid: 'V-222546'
  tag rid: 'SV-222546r879602_rule'
  tag stig_id: 'APSC-DV-001780'
  tag gtitle: 'SRG-APP-000165'
  tag fix_id: 'F-24205r493547_fix'
  tag 'documentable'
  tag legacy: ['SV-84197', 'V-69575']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
