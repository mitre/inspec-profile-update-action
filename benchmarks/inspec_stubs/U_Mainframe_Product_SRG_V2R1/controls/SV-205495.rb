control 'SV-205495' do
  title 'The Mainframe Product must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

To meet password policy requirements, passwords need to be changed at specific policy-based intervals. 

If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed per policy requirements.'
  desc 'check', 'If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine user account management configurations. 

If the Mainframe Product account management configuration does not prohibit password reuse for a minimum of five generations, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management to prohibit password reuse for a minimum of five generations.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5761r299718_chk'
  tag severity: 'medium'
  tag gid: 'V-205495'
  tag rid: 'SV-205495r397504_rule'
  tag stig_id: 'SRG-APP-000165-MFP-000237'
  tag gtitle: 'SRG-APP-000165'
  tag fix_id: 'F-5761r299719_fix'
  tag 'documentable'
  tag legacy: ['SV-82883', 'V-68393']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
