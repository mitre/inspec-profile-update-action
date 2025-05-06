control 'SV-254911' do
  title 'The Tanium application must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

To meet password policy requirements, passwords need to be changed at specific policy-based intervals.

If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Console Users:

Per guidance, Enterprise Console users are inherited via LDAP synchronization as such passwords are not managed or enforced at the Tanium application level. 

Local TanOS account: 

1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "C" for "User Administration Menu," and then press "Enter".

4. Press "L" for "Local Tanium User Management," and then press "Enter".

5. Press "B" for "Security Policy Local Authentication Service," and then press "Enter".

If the value of "Password History:" is less than "5", this is a finding.'
  desc 'fix', 'Console Users:

Per guidance, Enterprise Console users are inherited via LDAP synchronization as such passwords are not managed or enforced at the Tanium application level. 

Local TanOS account: 

1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "C" for "User Administration Menu," and then press "Enter".

4. Press "L" for "Local Tanium User Management," and then press "Enter".

5. Press "B" for "Security Policy Local Authentication Service," and then press "Enter".

6. Type "yes" and press "Enter".

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
  tag check_id: 'C-58524r867631_chk'
  tag severity: 'medium'
  tag gid: 'V-254911'
  tag rid: 'SV-254911r867633_rule'
  tag stig_id: 'TANS-AP-000430'
  tag gtitle: 'SRG-APP-000165'
  tag fix_id: 'F-58468r867632_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
