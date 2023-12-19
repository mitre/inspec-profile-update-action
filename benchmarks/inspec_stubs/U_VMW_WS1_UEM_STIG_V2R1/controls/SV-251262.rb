control 'SV-251262' do
  title 'The Workspace ONE UEM local accounts must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

To meet password policy requirements, passwords need to be changed at specific policy-based intervals. 

If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.

SFR ID: FMT_SMF.1(2)b. / IA-5 (1) (e)'
  desc 'check', 'Verify WS1 UEM is configured to prohibit password reuse for a minimum of five generations for local account passwords for the emergency local account.

1. Log in to the WS1UEM console.
2. Go to Settings >> Admin >> Console Security >> Passwords.
3. Verify "Enforced password history" to "5 passwords remembered".

If WS1 UEM is not configured to prohibit password reuse for a minimum of five generations for local account passwords, this is a finding.'
  desc 'fix', 'Configure WS1 UEM to prohibit password reuse for a minimum of five generations for local account passwords for the emergency local account.

1. Log in to the WS1UEM console.
2. Go to Settings >> Admin >> Console Security >> Passwords.
3. Configure "Enforced password history" to "5 passwords remembered".'
  impact 0.7
  ref 'DPMS Target VMware Workspace ONE UEM'
  tag check_id: 'C-54697r805087_chk'
  tag severity: 'high'
  tag gid: 'V-251262'
  tag rid: 'SV-251262r805089_rule'
  tag stig_id: 'VMW1-00-200150'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-54651r805088_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
