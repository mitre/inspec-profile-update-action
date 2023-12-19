control 'SV-203633' do
  title 'The operating system must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Verify the operating system prohibits password reuse for a minimum of five generations. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to prohibit password reuse for a minimum of five generations.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3758r557623_chk'
  tag severity: 'medium'
  tag gid: 'V-203633'
  tag rid: 'SV-203633r557625_rule'
  tag stig_id: 'SRG-OS-000077-GPOS-00045'
  tag gtitle: 'SRG-OS-000077'
  tag fix_id: 'F-3758r557624_fix'
  tag 'documentable'
  tag legacy: ['SV-70965', 'V-56705']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
