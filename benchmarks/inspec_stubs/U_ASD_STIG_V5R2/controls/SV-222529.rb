control 'SV-222529' do
  title 'The application must ensure users are authenticated with an individual authenticator prior to using a group authenticator.'
  desc 'To assure individual accountability and prevent unauthorized access, application users must be individually identified and authenticated. Individual accountability mandates that each user is uniquely identified.

A group authenticator is a shared account or some other form of authentication that allows multiple unique individuals to access the application using a single account.

If an application allows or provides for group authenticators, it must first individually authenticate users prior to implementing group authenticator functionality.

Some applications may not have the need to provide a group authenticator; this is considered a matter of application design. In those instances where the application design includes the use of a group authenticator, this requirement will apply.

There may also be instances when specific user actions need to be performed on the information system without unique user identification or authentication. An example of this type of access is a web server which contains publicly releasable information.'
  desc 'check', 'Review the application documentation, examine user accounts, group membership and interview the application administrator to identify group or shared accounts. Document the group or shared account information.

If the application does not use group or shared accounts, this requirement is not applicable.

Create a test account or use an existing group member account.

Ensure the test account is not authenticated to the application and attempt to access the application with the group account credentials.

If the application allows access without first requiring the group member to authenticate with their individual credentials, this is a finding.'
  desc 'fix', 'Design and configure the application to individually authenticate group account members prior to allowing access.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24199r493495_chk'
  tag severity: 'medium'
  tag gid: 'V-222529'
  tag rid: 'SV-222529r508029_rule'
  tag stig_id: 'APSC-DV-001610'
  tag gtitle: 'SRG-APP-000153'
  tag fix_id: 'F-24188r493496_fix'
  tag 'documentable'
  tag legacy: ['SV-84163', 'V-69541']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
