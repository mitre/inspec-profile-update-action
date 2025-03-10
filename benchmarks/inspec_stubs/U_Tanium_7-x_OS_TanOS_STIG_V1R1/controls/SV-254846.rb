control 'SV-254846' do
  title 'The Tanium Operating System (TanOS) must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "C" for "User Administration Menu".

4. Press "L" for "Local Tanium User Management".

5. Press "B" for "Security Policy Local Authentication Service".

If "Password Minimum Length" is not set to 15, this is a finding.'
  desc 'fix', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "C" for "User Administration Menu".

4. Press "L" for "Local Tanium User Management".

5. Press "B" for "Security Policy Local Authentication Service".

6. Type "Yes".

7. Press "Enter" to accept the current value for "Define the minimum password in days [0 - 20]".

8. Press "Enter" to accept the current value for "Define the maximum password lifetime in days [0-300]".

9. Set the value for "Define the maximum password length (characters) [0-30]" to "15".

11. Press "Enter" to accept the current values for the rest of the options.

12. Type "Yes" to apply the new security policy.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58459r866077_chk'
  tag severity: 'medium'
  tag gid: 'V-254846'
  tag rid: 'SV-254846r866079_rule'
  tag stig_id: 'TANS-OS-000285'
  tag gtitle: 'SRG-OS-000078'
  tag fix_id: 'F-58403r866078_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
