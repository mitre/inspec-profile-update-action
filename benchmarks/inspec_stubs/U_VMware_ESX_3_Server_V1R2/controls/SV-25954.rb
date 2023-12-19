control 'SV-25954' do
  title 'The system must prevent the use of dictionary words for passwords.'
  desc 'An easily guessable password provides an open door to any external or internal malicious intruder. Many computer compromises occur as the result of account name and password guessing. This is generally done by someone with an automated script using repeated logon attempts until the correct account and password pair is guessed. Utilities, such as cracklib, can be used to validate passwords are not dictionary words and meet other criteria during password changes.'
  desc 'check', 'Determine if the system prevents the use of dictionary words in passwords. If it does not, this is a finding.'
  desc 'fix', 'Configure the system to prevent the use of dictionary words in passwords.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29097r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22307'
  tag rid: 'SV-25954r1_rule'
  tag stig_id: 'GEN000790'
  tag gtitle: 'GEN000790'
  tag fix_id: 'F-26096r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000189']
  tag nist: ['IA-5 (4)']
end
