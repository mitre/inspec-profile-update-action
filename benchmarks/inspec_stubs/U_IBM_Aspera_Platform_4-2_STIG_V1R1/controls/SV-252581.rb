control 'SV-252581' do
  title 'IBM Aspera Faspex must lock accounts after three unsuccessful login attempts within a 15-minute timeframe.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'If the IBM Aspera Faspex feature of the Aspera Platform is not installed, this is Not Applicable.

Verify IBM Aspera Faspex locks accounts after three unsuccessful login attempts within a 15-minute timeframe: 

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege. 
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" section.
- Verify the "Faspex accounts" "Lock users" section is set to "3" or less failed login attempts within "15" minutes or less.

If the "Lock users" section is set to more than "3" failed login attempts, this is a finding.

If the "Lock users" section is set to more than "15" minutes, this is a finding.'
  desc 'fix', 'Configure IBM Aspera Faspex to lock accounts after three unsuccessful login attempts within a 15-minute timeframe: 

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege. 
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" section.
- Edit the "Faspex accounts" "Lock users" section failed login attempts option to "3" or less.
- Edit the "Lock users" section attempts within minutes to "15" or less.
- Select "Update" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56037r817911_chk'
  tag severity: 'medium'
  tag gid: 'V-252581'
  tag rid: 'SV-252581r817913_rule'
  tag stig_id: 'ASP4-FA-050170'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-55987r817912_fix'
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002236', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b', 'AC-7 b']
end
