control 'SV-76965' do
  title 'ColdFusion must set session cookies as browser session cookies.'
  desc 'Generating a unique session identifier for each session inhibits an attacker from using an already authenticated session identifier that has not been invalidated.  If an attacker is able to use an authenticated session, the attacker is given the privileges of the user who created the session.  This may allow the attacker to generate user accounts for later use, change configuration settings, deploy an application or change application modules and code for already hosted applications, or see usernames for trusted relationships to other resources.  It is important that each new session is given a new and unique session identifier and that old identifiers are discarded quickly.

ColdFusion offers the capability to set session Cookies and all other Cookies to browser cookies.  This means all cookies become invalid once the browser window is closed instead of setting a time to live to the cookie.  Setting the cookies to browser cookies will ensure the session identifier is invalidated once the user ends the session through closing the browser.'
  desc 'check', 'Within the Administrator Console, navigate to the "Memory Variables" page under the "Server Settings" menu.

If "Cookie Timeout" is not set to -1, this is a finding.'
  desc 'fix', 'Navigate to the "Memory Variables" page under the "Server Settings" menu.  Set the parameter "Cookie Timeout" to -1 and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63279r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62475'
  tag rid: 'SV-76965r1_rule'
  tag stig_id: 'CF11-05-000169'
  tag gtitle: 'SRG-APP-000223-AS-000150'
  tag fix_id: 'F-68395r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
