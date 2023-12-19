control 'SV-254861' do
  title 'Tanium must automatically lock accounts and require them be unlocked by an administrator when three unsuccessful login attempts in 15 minutes are exceeded.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', '1. Log in to Tanium interactively as a TanAdmin user.

2. Type "A" for "Appliance Configuration Menu".

3. Type "A" for Security.

4. Type "P" for Security Policy.

5. The section for "Account lockout:" should read "0 seconds after 3 failures".

If the section reads anything else, this is a finding.'
  desc 'fix', '1. Log in to Tanium interactively as a TanAdmin user. 

2. Type "A" for "Appliance Configuration Menu".

3. Type "A" for "Security". 

4. Type "P" for "Security Policy". 

5. Type "Account Lockout Time".

6. Set the account lockout time to "0".

Note: The time range for the three failures to occur is 15 minutes by default and cannot be configured otherwise.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58474r866122_chk'
  tag severity: 'medium'
  tag gid: 'V-254861'
  tag rid: 'SV-254861r866124_rule'
  tag stig_id: 'TANS-OS-000985'
  tag gtitle: 'SRG-OS-000329'
  tag fix_id: 'F-58418r866123_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
