control 'SV-235937' do
  title 'Oracle WebLogic must enforce the organization-defined time period during which the limit of consecutive invalid access attempts by a user is counted.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via automated user password guessing, otherwise known as brute-forcing, is reduced. Best practice requires a time period be applied in which the number of failed attempts is counted (Example: 5 failed attempts within 5 minutes). Limits are imposed by locking the account.

Application servers provide a management capability that allows a user to login via a web interface or a command shell. Application servers also utilize either a local user store or a centralized user store such as an LDAP server. As such, the authentication method employed by the application server must be able to limit the number of consecutive invalid access attempts within the specified time period regardless of access method or user store utilized.'
  desc 'check', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Configuration' tab -> 'User Lockout' tab
5. Ensure the following field values are set:
'Lockout Threshold' = 3
'Lockout Duration' = 15
'Lockout Reset Duration' = 15

If 'Lockout Threshold' is not set to 3 or 'Lockout Duration' is not set to 15 or 'Lockout Reset Duration' is not set to 15, this is a finding."
  desc 'fix', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Configuration' tab -> 'User Lockout' tab
5. Utilize 'Change Center' to create a new change session
6. Set the following values in the fields as shown:
'Lockout Threshold' = 3
'Lockout Duration' = 15
'Lockout Reset Duration' = 15
7. Click 'Save', and from 'Change Center' click 'Activate Changes' to enable configuration changes"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39156r628587_chk'
  tag severity: 'medium'
  tag gid: 'V-235937'
  tag rid: 'SV-235937r628589_rule'
  tag stig_id: 'WBLC-01-000033'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-39119r628588_fix'
  tag 'documentable'
  tag legacy: ['SV-70477', 'V-56223']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
