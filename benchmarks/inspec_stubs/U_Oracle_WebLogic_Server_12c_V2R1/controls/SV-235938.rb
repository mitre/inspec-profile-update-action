control 'SV-235938' do
  title 'Oracle WebLogic must automatically lock accounts when the maximum number of unsuccessful login attempts is exceeded for an organization-defined time period or until the account is unlocked by an administrator.'
  desc 'Anytime an authentication method is exposed so as to allow for the utilization of an application interface, there is a risk that attempts will be made to obtain unauthorized access.

By locking the account when the pre-defined number of failed login attempts has been exceeded, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.

Specifying a time period in which the account is to remain locked serves to obstruct the operation of automated password guessing tools while allowing a valid user to reinitiate login attempts after the expiration of the time period without administrative assistance.'
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
  tag check_id: 'C-39157r628590_chk'
  tag severity: 'medium'
  tag gid: 'V-235938'
  tag rid: 'SV-235938r628592_rule'
  tag stig_id: 'WBLC-01-000034'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-39120r628591_fix'
  tag 'documentable'
  tag legacy: ['SV-70479', 'V-56225']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
