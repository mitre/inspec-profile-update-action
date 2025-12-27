control 'SV-254913' do
  title 'The Tanium application must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals. 

One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised. 

This requirement does not include emergency administration accounts which are meant for access to the application in case of failure. These accounts are not required to have maximum password lifetime restrictions.'
  desc 'check', 'Console Users:

Per guidance, Enterprise Console users are inherited via LDAP synchronization as such passwords are not managed or enforced at the Tanium application level. 

Local TanOS account: 

1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Enter "C" for "User Administration Menu," and then press "Enter".

4. Enter "L" for " Local Tanium User Management," and then press "Enter".

5. Enter "B" for " Security Policy Local Authentication Service," and then press "Enter".

If the value of "Password Maximum Age (days):" is greater than "60", this is a finding.'
  desc 'fix', 'Console Users:

Per guidance, Enterprise Console users are inherited via LDAP synchronization as such passwords are not managed or enforced at the Tanium application level.

Local TanOS account: 

1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Enter "" for "User Administration Menu," and then press "Enter".

4. Enter "L" for "Local Tanium User Management," and then press "Enter".

5. Enter "B" for "Security Policy Local Authentication Service," and then press "Enter".

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
  tag check_id: 'C-58526r867637_chk'
  tag severity: 'medium'
  tag gid: 'V-254913'
  tag rid: 'SV-254913r867639_rule'
  tag stig_id: 'TANS-AP-000475'
  tag gtitle: 'SRG-APP-000174'
  tag fix_id: 'F-58470r867638_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
