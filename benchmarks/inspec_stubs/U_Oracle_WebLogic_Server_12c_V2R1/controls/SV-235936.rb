control 'SV-235936' do
  title 'Oracle WebLogic must limit the number of failed login attempts to an organization-defined number of consecutive invalid attempts that occur within an organization-defined time period.'
  desc 'Anytime an authentication method is exposed so as to allow for the login to an application, there is a risk that attempts will be made to obtain unauthorized access.

By limiting the number of failed login attempts that occur within a particular time period, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account once the number of failed attempts has been exceeded.'
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
  tag check_id: 'C-39155r628584_chk'
  tag severity: 'medium'
  tag gid: 'V-235936'
  tag rid: 'SV-235936r628586_rule'
  tag stig_id: 'WBLC-01-000032'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-39118r628585_fix'
  tag 'documentable'
  tag legacy: ['SV-70475', 'V-56221']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
