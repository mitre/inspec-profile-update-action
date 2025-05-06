control 'SV-235966' do
  title 'Oracle WebLogic must enforce minimum password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password length is one of several factors that helps to determine strength and how long it takes to crack a password. The shorter the password is, the lower the number of possible combinations that need to be tested before the password is compromised. 

Application servers either provide a local user store, or they integrate with enterprise user stores like LDAP. When the application server provides the user store and enforces authentication, the application server must enforce minimum password length.'
  desc 'check', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Password Validation' subtab
5. Select 'SystemPasswordValidator'
6. Select 'Configuration' tab -> 'Provider Specific' subtab
7. Ensure 'Minimum Password Length' field value is set to '15'

If the 'Minimum Password Length' field is not set to '15', this is a finding."
  desc 'fix', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Password Validation' subtab
5. Select 'SystemPasswordValidator'
6. Select 'Configuration' tab -> 'Provider Specific' subtab
7. Utilize 'Change Center' to create a new change session
8. Set 'Minimum Password Length' field value to '15'. Click 'Save'"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39185r628674_chk'
  tag severity: 'medium'
  tag gid: 'V-235966'
  tag rid: 'SV-235966r628676_rule'
  tag stig_id: 'WBLC-05-000160'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-39148r628675_fix'
  tag 'documentable'
  tag legacy: ['SV-70535', 'V-56281']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
