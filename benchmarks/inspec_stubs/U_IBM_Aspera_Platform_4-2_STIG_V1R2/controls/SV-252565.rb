control 'SV-252565' do
  title 'IBM Aspera Console must lock accounts after three unsuccessful login attempts within a 15-minute timeframe.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Verify IBM Aspera Console locks accounts after three unsuccessful login attempts within a 15-minute timeframe: 

- Log in to the IBM Aspera Console web page as a user with administrative privilege. 
- Select the "Configuration" tab.
- Select the "Defaults" tab.
- Scroll down to the "Security" section.
- Verify the "Deactivate Users" section is set to "3" or less failed login attempts within "15" minutes or less.

If the "Deactivate Users" section is set to more than "3" failed login attempts, this is a finding.

If the "Deactivate Users" section is set to more than "15" minutes, this is a finding.'
  desc 'fix', 'Configure IBM Aspera Console to lock accounts after three unsuccessful login attempts within a 15-minute timeframe: 

- Log in to the IBM Aspera Console web page as a user with administrative privilege. 
- Select the "Configuration" tab.
- Select the "Defaults" tab.
- Scroll down to the "Security" section.
- Edit the "Deactivate Users" section failed login attempts option to "3" or less.
- Edit the "Deactivate Users" section attempts within minutes to "15" or less.
- Select "Save" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56021r817863_chk'
  tag severity: 'medium'
  tag gid: 'V-252565'
  tag rid: 'SV-252565r831494_rule'
  tag stig_id: 'ASP4-CS-040180'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-55971r817864_fix'
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002236', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b', 'AC-7 b']
end
