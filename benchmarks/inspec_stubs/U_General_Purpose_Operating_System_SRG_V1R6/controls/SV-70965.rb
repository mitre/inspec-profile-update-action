control 'SV-70965' do
  title 'The operating system must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Verify the operating system prohibits password reuse for a minimum of five generations. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to prohibit password reuse for a minimum of five generations.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57275r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56705'
  tag rid: 'SV-70965r1_rule'
  tag stig_id: 'SRG-OS-000077-GPOS-00045'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-61601r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
