control 'SV-77353' do
  title 'Riverbed Optimization System (RiOS) must automatically lock the account until the locked account is released by an administrator when three unsuccessful login attempts in 15 minutes are exceeded.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Verify that RiOS is configured to limit the number of unsuccessful login attempts during a 15-minute period to 3.

Navigate to the device Management Console
Navigate to Configure >> Security >> Password Policy

Verify that "Login Attempts Before Lockout:" is set to "3"
Verify that "Timeout for User Login After Lockout (seconds)" is set to "900"

If "Login Attempts Before Lockout" is not set to "3" and/or "Timeout for User Login After Lockout (seconds)" is not set to "900", this is a finding.'
  desc 'fix', 'Configure RiOS to limit the number of unsuccessful login attempts to 3 during a 15-minute period.

Navigate to the device Management Console
Navigate to Configure >> Security >> Password Policy
Set the value of "Login Attempts Before Lockout:" to "3"
Set the value of "Timeout for User Login After Lockout (seconds);" to "900"

Click "Apply" to save the changes
Navigate to the top of the web page and click "Save" to write changes to memory'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63657r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62863'
  tag rid: 'SV-77353r1_rule'
  tag stig_id: 'RICX-DM-000026'
  tag gtitle: 'SRG-APP-000345-NDM-000290'
  tag fix_id: 'F-68781r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
