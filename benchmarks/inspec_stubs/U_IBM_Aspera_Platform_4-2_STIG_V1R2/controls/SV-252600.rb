control 'SV-252600' do
  title 'IBM Aspera Shares must lock accounts after three unsuccessful login attempts within a 15-minute timeframe.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'If the IBM Aspera Shares feature of the Aspera Platform is not installed, this is Not Applicable.

Verify IBM Aspera Shares locks accounts after three unsuccessful login attempts within a 15-minute timeframe: 

- Log in to the IBM Aspera Shares web page as a user with administrative privilege. 
- Select the "Admin" tab.
- Scroll down to the "Security" section.
- Select the "User Security" option.
- Verify the "Failed login count" is set to "3" or less.
- Verify the "Failed login interval" is set to "15" or less.

If the "Failed login count" is set to more than "3", this is a finding.

If the "Failed login interval" is set to more than "15" minutes, this is a finding.'
  desc 'fix', 'Configure IBM Aspera Shares to lock accounts after three unsuccessful login attempts within a 15-minute timeframe: 

- Log in to the IBM Aspera Shares web page as a user with administrative privilege. 
- Select the "Admin" tab.
- Scroll down to the "Security" section.
- Select the "User Security" option.
- Edit the "Failed login count" option to "3" or less.
- Edit the "Failed login interval" option to "15" minutes or less.
- Select "Save" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56056r817968_chk'
  tag severity: 'medium'
  tag gid: 'V-252600'
  tag rid: 'SV-252600r831511_rule'
  tag stig_id: 'ASP4-SH-060130'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-56006r817969_fix'
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002236', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b', 'AC-7 b']
end
