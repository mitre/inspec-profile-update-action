control 'SV-254843' do
  title 'The Tanium Operating System (TanOS) must enforce 24 hours/1 day as the maximum password lifetime.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "C" for "User Administration Menu".

4. Press "L" for "Local Tanium User Management".

5. Press "B" for "Security Policy Local Authentication Service".

If the "Password Minimum Age (days)" is not set to "1", this is a finding.'
  desc 'fix', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "C" for "User Administration Menu".

4. Press "L" for "Local Tanium User Management".

5. Press "B" for "Security Policy Local Authentication Service".

6. Type "Yes".

7. Set the value for "Define the minimum password in days [0 - 20]" to "1".

8. Press "Enter" to accept the current values for the rest of the options.

9. Type "Yes" to apply the new security policy.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58456r866068_chk'
  tag severity: 'medium'
  tag gid: 'V-254843'
  tag rid: 'SV-254843r866070_rule'
  tag stig_id: 'TANS-OS-000270'
  tag gtitle: 'SRG-OS-000075'
  tag fix_id: 'F-58400r866069_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
