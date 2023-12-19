control 'SV-207380' do
  title 'The VMM must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the VMM or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Verify the VMM prohibits password reuse for a minimum of five generations.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to prohibit password reuse for a minimum of five generations.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7637r365550_chk'
  tag severity: 'medium'
  tag gid: 'V-207380'
  tag rid: 'SV-207380r378763_rule'
  tag stig_id: 'SRG-OS-000077-VMM-000440'
  tag gtitle: 'SRG-OS-000077'
  tag fix_id: 'F-7637r365551_fix'
  tag 'documentable'
  tag legacy: ['SV-71211', 'V-56951']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
