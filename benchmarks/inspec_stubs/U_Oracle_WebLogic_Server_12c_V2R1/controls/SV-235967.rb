control 'SV-235967' do
  title 'Oracle WebLogic must enforce password complexity by the number of upper-case characters used.'
  desc "Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Use of a complex password helps to increase the time and resources required to compromise the password. 

Application servers either provide a local user store, or they integrate with enterprise user stores like LDAP. When the application server provides the user store and enforces authentication, the application server must enforce the organization's password complexity requirements, which includes the requirement to use a specific number of upper-case characters."
  desc 'check', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Password Validation' subtab
5. Select 'SystemPasswordValidator'
6. Select 'Configuration' tab -> 'Provider Specific' subtab
7. Ensure 'Minimum Number of Upper Case Characters' field value is set to '1' or higher

If the 'Minimum Number of Upper Case Characters' field value is not set to '1' or higher, this is a finding."
  desc 'fix', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Password Validation' subtab
5. Select 'SystemPasswordValidator'
6. Select 'Configuration' tab -> 'Provider Specific' subtab
7. Utilize 'Change Center' to create a new change session
8. Set 'Minimum Number of Upper Case Characters' field value to '1' or higher. Click 'Save'"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39186r628677_chk'
  tag severity: 'medium'
  tag gid: 'V-235967'
  tag rid: 'SV-235967r628679_rule'
  tag stig_id: 'WBLC-05-000162'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-39149r628678_fix'
  tag 'documentable'
  tag legacy: ['SV-70537', 'V-56283']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
