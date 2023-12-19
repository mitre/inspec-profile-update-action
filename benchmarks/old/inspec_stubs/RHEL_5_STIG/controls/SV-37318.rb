control 'SV-37318' do
  title 'The system must prevent the use of dictionary words for passwords.'
  desc 'An easily guessable password provides an open door to any external or internal malicious intruder.  Many computer compromises occur as the result of account name and password guessing.  This is generally done by someone with an automated script that uses repeated logon attempts until the correct account and password pair is guessed.  Utilities, such as cracklib, can be used to validate passwords are not dictionary words and meet other criteria during password changes.'
  desc 'fix', 'If /etc/pam.d/system-auth references /etc/pam.d/system-auth-ac refer to the man page for system-auth-ac for a description of how to add options not configurable with authconfig. Edit /etc/pam.d/system-auth and configure pam_cracklib by adding a line such as "password required pam_cracklib.so"'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22307'
  tag rid: 'SV-37318r1_rule'
  tag stig_id: 'GEN000790'
  tag gtitle: 'GEN000790'
  tag fix_id: 'F-31262r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000189']
  tag nist: ['IA-5 (4)']
end
