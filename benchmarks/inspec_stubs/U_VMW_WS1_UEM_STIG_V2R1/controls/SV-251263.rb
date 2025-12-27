control 'SV-251263' do
  title 'The Workspace ONE UEM must enforce the limit of three consecutive invalid logon attempts by a user.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.

SFR ID: FMT_SMF.1(2)b. / IA-7-a'
  desc 'check', 'Verify WS1 UEM is configured to enforce a limit of three invalid logon attempts for a local account.

1. Log in to the WS1UEM console.
2. Go to Settings >> Admin >> Console Security >> Passwords.
3. Verify "Maximum invalid login attempts" is set to 3.

If WS1 UEM is not configured to enforce a limit of three invalid logon attempts for a local account, this is a finding.'
  desc 'fix', 'Configure WS1 UEM to enforce a limit of three invalid logon attempts for a local account.

1. Log in to the WS1UEM console.
2. Go to Settings >> Admin >> Console Security >> Passwords.
3. Configure "Maximum invalid login attempts" to 3.'
  impact 0.7
  ref 'DPMS Target VMware Workspace ONE UEM'
  tag check_id: 'C-54698r806439_chk'
  tag severity: 'high'
  tag gid: 'V-251263'
  tag rid: 'SV-251263r805093_rule'
  tag stig_id: 'VMW1-00-200180'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-54652r806440_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
