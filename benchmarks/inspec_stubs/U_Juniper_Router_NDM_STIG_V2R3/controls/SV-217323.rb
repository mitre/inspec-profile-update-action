control 'SV-217323' do
  title 'The Juniper router must be configured to enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement as shown in the example below.

system {
   …
   …
   …
    login {
        password {
            minimum-length 15;
        }        
    }

If the router is not configured to enforce a minimum 15-character password length, this is a finding.'
  desc 'fix', 'Configure the router to enforce a minimum 15-character password length as shown in the example below.

[edit system login]
set password minimum-length 15'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18550r296547_chk'
  tag severity: 'medium'
  tag gid: 'V-217323'
  tag rid: 'SV-217323r879601_rule'
  tag stig_id: 'JUNI-ND-000550'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-18548r296548_fix'
  tag 'documentable'
  tag legacy: ['SV-101231', 'V-91131']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
