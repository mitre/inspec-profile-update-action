control 'SV-254845' do
  title 'The Tanium Operating System (TanOS) must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "C" for "User Administration Menu".

4. Press "L" for "Local Tanium User Management".

5. Press "B" for "Security Policy Local Authentication Service".

If "Password History" is not set to "5", this is a finding.'
  desc 'fix', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "C" for "User Administration Menu".

4. Press "L" for "Local Tanium User Management".

5. Press "B" for "Security Policy Local Authentication Service".

6. Type "Yes".

7. Press "Enter" to accept the current value for "Define the minimum password in days [0 - 20]".

8. Press "Enter" to accept the current value for "Define the maximum password lifetime in days [0-300]".

9. Press "Enter" to accept the current value for "Define the maximum password length (characters) [0-30]".

10. Set the value for "Define the minimum password history counter [0-10]" to "5".

11. Press "Enter" to accept the current values for the rest of the options.

12. Type "Yes" to apply the new security policy.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58458r866074_chk'
  tag severity: 'medium'
  tag gid: 'V-254845'
  tag rid: 'SV-254845r866076_rule'
  tag stig_id: 'TANS-OS-000280'
  tag gtitle: 'SRG-OS-000077'
  tag fix_id: 'F-58402r866075_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
