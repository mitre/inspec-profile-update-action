control 'SV-222549' do
  title 'The application must terminate existing user sessions upon account deletion.'
  desc %q(The application must ensure that a user does not retain any rights that may have been granted or retain access to the application after the user's authorization or role within the application has been deleted or modified.  This means once a user's role/account within the application has been modified, deleted or disabled, the changes must be enforced immediately within the application.  Any privileges or access the user had prior to the change must not be retained.  For example; any application sessions that the user may have already established prior to the configuration change must be terminated when the user account changes occur.

Simply removing a user from a web application without terminating any existing application user sessions can introduce a scenario where the deleted user still has access to the application even though their account has been deleted from the authentication store. This can be attributed to browser caching and session management on the web server.

To address this, the web application must provide a means for ensuring this type of "zombie" access does not occur. Applications must provide a user management feature or function that will terminate any existing user sessions at the same time or just before the user account is terminated from the authoritative authentication source.)
  desc 'check', 'Review the application documentation and interview the application administrator.

Identify the user management functions of the application and create a test user account.

Access the application and perform application functions as the test user.

Access the user management functions and delete the test account while the test user sessions are still active.

Verify the test user application sessions are terminated by attempting to perform additional application functions.

If the test user retains access after the test account has been deleted, this is a finding.'
  desc 'fix', 'Configure the application to terminate existing sessions of users whose accounts are deleted.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24219r493555_chk'
  tag severity: 'medium'
  tag gid: 'V-222549'
  tag rid: 'SV-222549r849465_rule'
  tag stig_id: 'APSC-DV-001800'
  tag gtitle: 'SRG-APP-000400'
  tag fix_id: 'F-24208r493556_fix'
  tag 'documentable'
  tag legacy: ['SV-84769', 'V-70147']
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
