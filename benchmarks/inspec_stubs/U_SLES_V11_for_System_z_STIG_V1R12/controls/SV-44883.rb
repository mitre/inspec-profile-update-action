control 'SV-44883' do
  title 'The system must prevent the use of dictionary words for passwords.'
  desc 'An easily guessable password provides an open door to any external or internal malicious intruder.  Many computer compromises occur as the result of account name and password guessing.  This is generally done by someone with an automated script that uses repeated logon attempts until the correct account and password pair is guessed.  Utilities, such as cracklib, can be used to validate passwords are not dictionary words and meet other criteria during password changes.'
  desc 'check', 'Check /etc/pam.d/common-password for pam_cracklib configuration.
# grep pam_cracklib /etc/pam.d/common-password*
If pam_cracklib is not present, this is a finding.



Ensure the passwd command uses the common-password settings.
# grep common-password /etc/pam.d/passwd

If a line "password include common-password" is not found then the password checks in common-password will not be applied to new passwords, this is a finding.'
  desc 'fix', 'Edit /etc/pam.d/common-password and configure pam_cracklib by adding a line such as "password  required pam_cracklib.so"'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42337r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22307'
  tag rid: 'SV-44883r1_rule'
  tag stig_id: 'GEN000790'
  tag gtitle: 'GEN000790'
  tag fix_id: 'F-38315r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000189']
  tag nist: ['IA-5 (4)']
end
