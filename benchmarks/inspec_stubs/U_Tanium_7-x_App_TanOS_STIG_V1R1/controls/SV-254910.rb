control 'SV-254910' do
  title 'The Tanium application must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Console Users:

Per guidance, Enterprise Console users are inherited via LDAP synchronization, as such passwords are not managed or enforced at the Tanium application level. 

Local TanOS account: 

1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "C" for "User Administration Menu," and then press "Enter".

4. Press "L" for "Local Tanium User Management," and then press "Enter".

5. Press "B" for "Security Policy Local Authentication Service," and then press "Enter".

If the value of "Password Minimum Length:" is less than "15", this is a finding.'
  desc 'fix', 'Console Users:

Per guidance, Enterprise Console users are inherited via LDAP synchronization, as such passwords are not managed or enforced at the Tanium application level. 

Local TanOS account: 

1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "C" for "User Administration Menu," and then press "Enter".

4. Press "L" for "Local Tanium User Management," and then press "Enter".

5. Press "B" for "Security Policy Local Authentication Service," and then press "Enter".

6. Type "yes," and then press "Enter".

7. Input the following settings, pressing "Enter" after every value:
    a) Minimum Password Lifetime - 1
    b) Maximum Password Lifetime - 60
    c) Minimum Password Length - 15
    d) Minimum Password History - 5
    e) Password Lockout - TRUE
    f) Maximum Password Attempts - 3

8. Type "yes" to accept the new password policy.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58523r867628_chk'
  tag severity: 'medium'
  tag gid: 'V-254910'
  tag rid: 'SV-254910r867630_rule'
  tag stig_id: 'TANS-AP-000425'
  tag gtitle: 'SRG-APP-000164'
  tag fix_id: 'F-58467r867629_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
