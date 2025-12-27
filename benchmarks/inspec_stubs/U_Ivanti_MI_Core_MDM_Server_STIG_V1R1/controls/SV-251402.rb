control 'SV-251402' do
  title 'The Ivanti MobileIron Core server must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.

'
  desc 'check', 'Verify the Ivanti MobileIron Core server is configured to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.

In the Core server, navigate to the following: Settings >> Security >> Password Policy.

Verify the number of failed attempts is set to 3 and Auto-Lock Time is set to 900 seconds.

If the number of failed attempts is not set to 3 and Auto-Lock Time is not set to 900 seconds, this is a finding.'
  desc 'fix', 'Configure the Ivanti MobileIron Core server to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.

Go to Settings >> Security >> Password Policy. Set Number of Failed attempts to 3 and set Auto-Lock Time to 900 seconds.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54837r806336_chk'
  tag severity: 'medium'
  tag gid: 'V-251402'
  tag rid: 'SV-251402r806338_rule'
  tag stig_id: 'IMIC-11-001400'
  tag gtitle: 'SRG-APP-000065-UEM-000036'
  tag fix_id: 'F-54790r806337_fix'
  tag satisfies: ['FMT_SMF.1(2)b.\nReference: PP-MDM-431028']
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
