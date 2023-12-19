control 'SV-254912' do
  title 'Tanium must enforce 24 hours/1 day as the minimum password lifetime.'
  desc 'Enforcing a minimum password lifetime helps prevent repeated password changes to defeat the password reuse or history enforcement requirement.'
  desc 'check', 'Console Users:

Per guidance, Enterprise Console users are inherited via LDAP synchronization as such passwords are not managed or enforced at the Tanium application level. 

Local TanOS account: 

1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "C" for "User Administration Menu," and then press "Enter".

4. Press "L" for " Local Tanium User Management," and then press "Enter".

5. Press "B" for " Security Policy Local Authentication Service," and then press "Enter".

If the value of "Password Minimum Age (days):" is greater than "1", this is a finding.'
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
  tag check_id: 'C-58525r867634_chk'
  tag severity: 'medium'
  tag gid: 'V-254912'
  tag rid: 'SV-254912r867636_rule'
  tag stig_id: 'TANS-AP-000470'
  tag gtitle: 'SRG-APP-000173'
  tag fix_id: 'F-58469r867635_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
