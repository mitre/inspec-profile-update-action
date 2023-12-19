control 'SV-95631' do
  title 'AAA Services must be configured to prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

To meet password policy requirements, passwords need to be changed at specific policy-based intervals. 

If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. This requirement is not applicable to service account passwords (e.g. shared secrets, pre-shared keys) or the account of last resort.

Where passwords are used, such as temporary or emergency accounts, verify AAA Services are configured to prohibit password reuse for a minimum of five generations. This requirement may be verified by demonstration or configuration review. 

If AAA Services are not configured to prohibit password reuse for a minimum of five generations, this is a finding.'
  desc 'fix', 'Configure AAA Services to prohibit password reuse for a minimum of five generations. This requirement is not applicable to service account passwords (e.g. shared secrets, pre-shared keys) or the account of last resort.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80659r3_chk'
  tag severity: 'medium'
  tag gid: 'V-80921'
  tag rid: 'SV-95631r1_rule'
  tag stig_id: 'SRG-APP-000165-AAA-000550'
  tag gtitle: 'SRG-APP-000165-AAA-000550'
  tag fix_id: 'F-87777r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
