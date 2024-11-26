control 'SV-254839' do
  title 'The Tanium Operating System (TanOS) must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "C" for "User Administration Menu," and then press "Enter".

4. Press L for "Local Tanium User Management," and then press "Enter".

5. Press "B" for "Security Policy Local Authentication Service," and then press "Enter".

If the value of "Maximum Password Attempts:" is greater than "3", this is a finding.'
  desc 'fix', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "C" for "User Administration Menu," and then press "Enter".

4. Press "L" for "Local Tanium User Management," and then press "Enter".

5. Press B for "Security Policy Local Authentication Service," and then press "Enter".

6. Type "yes," and then press "Enter".

7. Input the following settings pressing "Enter" after every value:
    a) Minimum Password Lifetime: Configure an appropriate value
    b) Maximum Password Lifetime: Configure an appropriate value
    c) Minimum Password Length: Configure an appropriate value
    d) Minimum Password History: Configure an appropriate value
    e) Password Lockout: Configure an appropriate value
    f) Maximum Password Attempts: 3

8. Type "yes" to accept the new password policy.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58452r866056_chk'
  tag severity: 'medium'
  tag gid: 'V-254839'
  tag rid: 'SV-254839r866058_rule'
  tag stig_id: 'TANS-OS-000070'
  tag gtitle: 'SRG-OS-000021'
  tag fix_id: 'F-58396r866057_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
